"""Execute one job the server assigned: validate, scan, report.

Order matters, and every step can end the job without the next one running:

1. **Validate** the assignment strictly (:func:`protocol.parse_assignment`). A
   job type, scanner or image name outside the closed sets is refused and
   reported — nothing is executed for it.
2. **Check the tools** each scanner needs are installed and usable. If not,
   the job is handed back (``retryable``) for a runner that has them.
3. **Scan** each requested scanner in turn against
   ``<rotsy-server-host>/<name>:<tag>`` — the server's job-scoped registry
   proxy, with the job's own credential in the scanner's environment. No
   other registry, no Nexus credential, no container runtime.
4. **Report** progress throughout (which also renews the job's lease and is
   how a cancellation arrives), then the structured result.

The runner never receives a command line. The only inputs that reach a
scanner's argument vector are the validated image name/tag and paths the
runner chose itself.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from urllib.parse import urlsplit

from .client import ClientError, JobGone, ServerClient, ServerError
from .config import Config
from .logs import register_secret
from .protocol import MAX_FINDINGS, JobAssignment, clean_finding, parse_assignment
from .scanners import grype, trivy
from .scanners.base import Credentials, ScanOutcome, assert_static_ref
from .tools import ToolManager

logger = logging.getLogger(__name__)


#: Progress window each scanner reports within, by position.
class JobCancelled(Exception):
    pass


class Executor:
    #: Base of the exponential delay between result-delivery retries (seconds).
    retry_base: float = 2.0

    def __init__(self, config: Config, client: ServerClient, tools: ToolManager) -> None:
        self._config = config
        self._client = client
        self._tools = tools
        parts = urlsplit(client.server_url)
        #: host[:port] of the Rotsy server — where the registry proxy lives.
        self.registry_host = parts.netloc
        #: Plain-http server (local test setups only): the scanners must talk
        #: plain HTTP to the proxy too.
        self.insecure_registry = parts.scheme == "http" or not config.tls_verify
        self._last: dict[str, tuple[int, str, str]] = {}

    def image_ref(self, job: JobAssignment) -> str:
        ref = f"{self.registry_host}/{job.target.name}:{job.target.tag}"
        assert_static_ref(ref)
        return ref

    async def run(self, raw: dict, cancel: asyncio.Event | None = None) -> str:
        """Run one assignment end to end. Returns the final status for logs."""
        cancel = cancel or asyncio.Event()
        job, reason = parse_assignment(raw)
        job_uid = str(raw.get("job_uid") or "")[:64] if isinstance(raw, dict) else ""
        if job is None:
            logger.warning("Refusing malformed job %s: %s", job_uid or "?", reason)
            if job_uid:
                await self._report_failure(job_uid, f"runner refused a malformed job: {reason}", retryable=False)
            return "refused"
        register_secret(job.target.registry.password)

        for scanner in job.scanners:
            ok, why = self._tools.ready_for(scanner)
            if not ok:
                logger.warning(
                    "Job %s needs %s, which is not ready here (%s); handing it back", job.job_uid, scanner, why
                )
                await self._report_failure(job.job_uid, f"{scanner} is not ready on this runner: {why}", retryable=True)
                return "handed-back"

        keepalive = asyncio.create_task(self._keepalive(job, cancel))
        try:
            outcomes = await self._scan_all(job, cancel)
        except JobCancelled:
            await self._report_failure(job.job_uid, "cancelled", retryable=False)
            return "cancelled"
        except JobGone:
            logger.warning("Job %s was taken away by the server; dropping it", job.job_uid)
            return "dropped"
        finally:
            keepalive.cancel()
            await asyncio.gather(keepalive, return_exceptions=True)
            self._last.pop(job.job_uid, None)

        results = [self._result(o) for o in outcomes]
        for attempt in range(1, 6):
            try:
                await self._client.complete(job.job_uid, results)
                logger.info(
                    "Job %s complete: %s",
                    job.job_uid,
                    ", ".join(f"{o.scanner}={'ok' if o.ok else 'failed'}" for o in outcomes),
                )
                return "completed"
            except JobGone:
                logger.warning("Job %s is no longer ours; its result was discarded by the server", job.job_uid)
                return "dropped"
            except ServerError as exc:
                logger.warning("Could not deliver job %s result (attempt %d/5): %s", job.job_uid, attempt, exc)
                await asyncio.sleep(min(30.0, self.retry_base**attempt))
            except ClientError as exc:
                logger.error("Server refused job %s result: %s", job.job_uid, exc)
                return "rejected"
        return "undelivered"

    async def _scan_all(self, job: JobAssignment, cancel: asyncio.Event) -> list[ScanOutcome]:
        """Run the job's scanners side by side.

        They are independent static reads of the same image (separate
        binaries, databases and locks), so a job takes as long as the slower
        scanner instead of the sum of both.
        """
        image_ref = self.image_ref(job)
        creds = Credentials(job.target.registry.username, job.target.registry.password)
        timeout = min(self._config.scan_timeout_seconds, max(30, job.timeout_seconds))
        await self._progress(job, 5, f"{', '.join(job.scanners)}: scanning {job.target.image}", "scanning", cancel)
        tasks = {asyncio.create_task(self._scan_one(s, image_ref, creds, timeout)): s for s in job.scanners}
        waiter = asyncio.create_task(cancel.wait())
        outcomes: dict[str, ScanOutcome] = {}
        pending = set(tasks)
        try:
            while pending:
                done, pending = await asyncio.wait(pending | {waiter}, return_when=asyncio.FIRST_COMPLETED)
                if waiter in done:
                    raise JobCancelled()
                pending.discard(waiter)
                for task in done:
                    scanner = tasks[task]
                    outcome = outcomes[scanner] = task.result()
                    await self._progress(
                        job,
                        5 + 90 * len(outcomes) // len(tasks),
                        f"{scanner}: {'done' if outcome.ok else 'failed'} — {len(outcome.vulnerabilities)} finding(s)",
                        "scanned",
                        cancel,
                    )
        finally:
            # Cancelling a scan task kills its scanner process group
            # (see scanners.base.exec_scanner).
            for task in (waiter, *tasks):
                if not task.done():
                    task.cancel()
            await asyncio.gather(waiter, *tasks, return_exceptions=True)
        return [outcomes[s] for s in job.scanners]

    async def _scan_one(self, scanner: str, image_ref: str, creds: Credentials, timeout: int) -> ScanOutcome:
        record = self._tools.record(scanner)
        version = record.version if record else ""
        try:
            async with self._tools.locks[scanner].read():
                binary = self._tools.binary(scanner)
                if binary is None:
                    return ScanOutcome(scanner, False, error=f"{scanner} binary disappeared")
                if scanner == "trivy":
                    return await trivy.run(
                        str(binary),
                        self._tools.trivy_cache_dir,
                        image_ref,
                        creds,
                        insecure=self.insecure_registry,
                        timeout=timeout,
                        tool_version=version,
                    )
                db = self._tools.record("grype-db")
                return await grype.run(
                    str(binary),
                    self._tools.grype_db_dir,
                    image_ref,
                    creds,
                    insecure=self.insecure_registry,
                    timeout=timeout,
                    tool_version=version,
                    db_version=db.version if db else "",
                )
        except (OSError, ValueError) as exc:
            logger.exception("%s could not be started", scanner)
            return ScanOutcome(scanner, False, error=f"{type(exc).__name__}: {exc}")

    async def _progress(
        self, job: JobAssignment, percent: int, message: str, stage: str, cancel: asyncio.Event
    ) -> None:
        self._last[job.job_uid] = (percent, message, stage)
        try:
            resp = await self._client.progress(job.job_uid, percent, message, stage)
        except ServerError as exc:
            logger.warning("Progress report for %s failed (continuing): %s", job.job_uid, exc)
            return
        if resp.cancel_requested:
            cancel.set()

    async def _keepalive(self, job: JobAssignment, cancel: asyncio.Event) -> None:
        """Renew the lease during long scans; it is also how a cancel arrives."""
        interval = max(5.0, job.lease_seconds / 3)
        while True:
            await asyncio.sleep(interval)
            percent, message, stage = self._last.get(job.job_uid, (0, "", ""))
            try:
                resp = await self._client.progress(job.job_uid, percent, message, stage)
            except JobGone:
                cancel.set()
                return
            except ServerError as exc:
                logger.warning("Lease renewal for %s failed: %s", job.job_uid, exc)
                continue
            if resp.cancel_requested:
                cancel.set()

    async def _report_failure(self, job_uid: str, error: str, *, retryable: bool) -> None:
        try:
            await self._client.fail(job_uid, error, retryable=retryable)
        except ClientError as exc:
            logger.warning("Could not report failure of job %s: %s", job_uid, exc)

    @staticmethod
    def _result(outcome: ScanOutcome) -> dict:
        data = asdict(outcome)
        findings = [clean_finding(f) for f in data.pop("vulnerabilities")[:MAX_FINDINGS]]
        return {
            "scanner": data["scanner"],
            "ok": data["ok"],
            "tool_version": data["tool_version"][:64],
            "db_version": data["db_version"][:64],
            "duration_ms": max(0, data["duration_ms"]),
            "error": data["error"][:2000],
            "detail": data["detail"][:8000],
            "findings": findings,
        }

"""The runner agent: heartbeat, tool sync, job loop, commands, shutdown.

Three cooperating loops on one event loop:

* **heartbeat** — reports identity, state and the tool inventory every
  ``heartbeat_interval_seconds`` (the server sets it) and applies the typed
  commands the server answers with: ``SYNC_TOOLS``, ``CANCEL_JOB``,
  ``SHUTDOWN``. Nothing else is accepted; an unknown command is logged and
  ignored.
* **workers** — ``concurrency`` of them, each long-polling ``/jobs/claim`` and
  running what it gets through the :class:`~rotsy_runner.executor.Executor`.
* **tool sync** — on start and on ``SYNC_TOOLS``, reconciles installed tools
  with the server's manifest (one sync at a time).

Failure handling:

* network errors and 5xx: exponential backoff with jitter (1s → 60s), then
  carry on — a server restart or a network blip is survived without exiting;
* 401 (credential rejected — deleted, reset, or never valid): stop claiming,
  stop heartbeating, exit with status 3. Fail closed; never retry a revoked
  credential in a loop;
* 403 (disabled): keep heartbeating so the UI shows the runner, take no work;
* SIGTERM / SIGINT / ``SHUTDOWN``: stop claiming, let running scans finish for
  up to ``ROTSY_RUNNER_SHUTDOWN_GRACE_SECONDS``, hand back anything still
  running (retryable, so another runner picks it up), send a final heartbeat.
"""

from __future__ import annotations

import asyncio
import logging
import random
import signal
from typing import Any

from . import PROTOCOL_VERSION, __version__, hostinfo
from .client import AuthError, ClientError, DisabledError, ServerClient, ServerError
from .config import Config
from .executor import Executor
from .logs import register_secret
from .state import Identity
from .tools import ToolManager

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_AUTH = 3
CAPABILITIES = ["container_scan", "scanner:trivy", "scanner:grype"]


class Backoff:
    def __init__(self, base: float = 1.0, cap: float = 60.0) -> None:
        self._base = base
        self._cap = cap
        self.failures = 0

    def reset(self) -> None:
        self.failures = 0

    def next(self) -> float:
        self.failures += 1
        delay = min(self._cap, self._base * (2 ** min(self.failures - 1, 10)))
        return delay * (0.5 + random.random() / 2)  # noqa: S311 - jitter, not security


class Agent:
    def __init__(
        self,
        config: Config,
        identity: Identity,
        credential: str,
        *,
        client: ServerClient | None = None,
        tools: ToolManager | None = None,
    ) -> None:
        register_secret(credential)
        self.config = config
        self.identity = identity
        self.client = client or ServerClient(config, identity.server_url, credential)
        self.tools = tools or ToolManager(config)
        self.executor = Executor(config, self.client, self.tools)
        self.heartbeat_interval = 15.0
        self.enabled = True
        self.exit_code = EXIT_OK
        self.last_error = ""
        self._stopping = asyncio.Event()
        self._sync_requested = asyncio.Event()
        # Workers wait for the first tool sync to finish (successfully or not)
        # so a job is not claimed only to be handed straight back.
        self._first_sync_done = asyncio.Event()
        self._running: dict[str, tuple[asyncio.Task, asyncio.Event]] = {}

    # --- facts -----------------------------------------------------------------
    def _state(self) -> str:
        if self._stopping.is_set():
            return "draining"
        if self.tools.syncing:
            return "syncing"
        return "busy" if self._running else "idle"

    def heartbeat_body(self) -> dict[str, Any]:
        os_name, arch = hostinfo.current()
        return {
            "state": self._state(),
            "version": __version__,
            "hostname": hostinfo.hostname(),
            "os": os_name,
            "arch": arch,
            "protocol_version": PROTOCOL_VERSION,
            "capabilities": CAPABILITIES,
            "concurrency": self.config.concurrency,
            "tools": self.tools.report(),
            "running_jobs": list(self._running)[:64],
            "last_error": self.last_error[:2000],
        }

    # --- lifecycle ---------------------------------------------------------------
    def request_stop(self, reason: str = "") -> None:
        if not self._stopping.is_set():
            logger.info("Stopping%s", f": {reason}" if reason else "")
            self._stopping.set()

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self.request_stop, f"received {sig.name}")
            except (NotImplementedError, RuntimeError):  # pragma: no cover - non-main thread / platform
                pass

    async def run(self) -> int:
        self._install_signal_handlers()
        logger.info(
            "rotsy-runner %s — runner %s (%s) → %s",
            __version__,
            self.identity.name,
            self.identity.runner_uid,
            self.identity.server_url,
        )
        self._sync_requested.set()  # reconcile tools once at start
        tasks = [
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat"),
            asyncio.create_task(self._sync_loop(), name="tool-sync"),
            *(asyncio.create_task(self._worker(i), name=f"worker-{i}") for i in range(self.config.concurrency)),
        ]
        await self._stopping.wait()
        await self._drain()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.exit_code != EXIT_AUTH:
            try:
                await self.client.heartbeat(self.heartbeat_body())
            except ClientError:
                pass
        await self.client.aclose()
        return self.exit_code

    async def _drain(self) -> None:
        if not self._running:
            return
        logger.info("Waiting up to %ds for %d running job(s)", self.config.shutdown_grace_seconds, len(self._running))
        tasks = [task for task, _ in self._running.values()]
        _done, pending = await asyncio.wait(tasks, timeout=self.config.shutdown_grace_seconds)
        for job_uid, (task, _cancel) in list(self._running.items()):
            if task in pending:
                task.cancel()
                try:
                    await self.client.fail(job_uid, "runner shutting down", retryable=True)
                except ClientError:
                    pass
        await asyncio.gather(*pending, return_exceptions=True)

    def _auth_failed(self, exc: AuthError) -> None:
        logger.error(
            "The server rejected this runner's credential (%s). The runner was deleted or its "
            "registration reset; register it again with a new enrollment token.",
            exc,
        )
        self.exit_code = EXIT_AUTH
        self.request_stop("credential rejected")

    # --- heartbeat + commands ---------------------------------------------------
    async def heartbeat_once(self) -> None:
        await self.tools.refresh_probes()
        resp = await self.client.heartbeat(self.heartbeat_body())
        self.heartbeat_interval = float(resp.heartbeat_interval_seconds)
        was_enabled, self.enabled = self.enabled, resp.runner_status == "active"
        if was_enabled != self.enabled:
            logger.warning("Runner %s on the server", "enabled" if self.enabled else "DISABLED")
        for command in resp.known_commands():
            self.apply(command.type, command.job_uid, command.reason)

    def apply(self, kind: str, job_uid: str | None = None, reason: str = "") -> None:
        if kind == "SYNC_TOOLS":
            self._sync_requested.set()
        elif kind == "CANCEL_JOB" and job_uid:
            running = self._running.get(job_uid)
            if running is not None:
                logger.info("Cancelling job %s: %s", job_uid, reason or "requested by the server")
                running[1].set()
        elif kind == "SHUTDOWN":
            self.request_stop(reason or "requested by the server")

    async def _heartbeat_loop(self) -> None:
        backoff = Backoff()
        while not self._stopping.is_set():
            try:
                await self.heartbeat_once()
                backoff.reset()
                self.last_error = ""
                delay = self.heartbeat_interval
            except AuthError as exc:
                self._auth_failed(exc)
                return
            except (ServerError, DisabledError, ClientError) as exc:
                self.last_error = str(exc)[:500]
                delay = backoff.next()
                logger.warning("Heartbeat failed (%s); retrying in %.0fs", exc, delay)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=delay)
            except TimeoutError:
                pass

    async def _sync_loop(self) -> None:
        backoff = Backoff(base=5.0, cap=300.0)
        while not self._stopping.is_set():
            await self._sync_requested.wait()
            self._sync_requested.clear()
            try:
                await self.tools.sync(self.client)
                backoff.reset()
                self._first_sync_done.set()
                # Tell the server straight away rather than at the next tick.
                await self.heartbeat_once()
            except AuthError as exc:
                self._auth_failed(exc)
                return
            except DisabledError:
                self._first_sync_done.set()
                logger.info("Runner disabled; skipping tool sync")
            except ClientError as exc:
                self._first_sync_done.set()
                delay = backoff.next()
                logger.warning("Tool sync failed (%s); retrying in %.0fs", exc, delay)
                await asyncio.sleep(delay)
                self._sync_requested.set()

    # --- work -------------------------------------------------------------------
    async def _worker(self, index: int) -> None:
        backoff = Backoff()
        await self._first_sync_done.wait()
        loop = asyncio.get_running_loop()
        while not self._stopping.is_set():
            if not self.enabled or self.tools.syncing:
                await asyncio.sleep(2)
                continue
            started = loop.time()
            try:
                assignment = await self.client.claim(wait_seconds=20, capacity=self.config.concurrency)
                backoff.reset()
            except AuthError as exc:
                self._auth_failed(exc)
                return
            except DisabledError:
                self.enabled = False
                continue
            except ClientError as exc:
                delay = backoff.next()
                logger.warning("Claim failed (%s); retrying in %.0fs", exc, delay)
                await asyncio.sleep(delay)
                continue
            if assignment is None:
                # The server holds an empty claim open (long poll). One that
                # answers instantly must not turn this loop into a hot spin.
                if loop.time() - started < 1.0:
                    await asyncio.sleep(1.0)
                continue
            job_uid = str(assignment.get("job_uid") or f"unknown-{index}")[:64]
            cancel = asyncio.Event()
            task = asyncio.create_task(self.executor.run(assignment, cancel), name=f"job-{job_uid}")
            self._running[job_uid] = (task, cancel)
            try:
                status = await asyncio.shield(task)
                logger.info("Job %s finished: %s", job_uid, status)
            except asyncio.CancelledError:
                if not task.done():
                    cancel.set()
                raise
            except Exception:  # noqa: BLE001 - one job's crash must not stop the worker
                logger.exception("Job %s crashed", job_uid)
                try:
                    await self.client.fail(job_uid, "runner error while executing the job", retryable=True)
                except ClientError:
                    pass
            finally:
                if task.done():
                    self._running.pop(job_uid, None)

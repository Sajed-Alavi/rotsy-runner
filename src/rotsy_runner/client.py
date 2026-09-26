"""HTTP client for the Rotsy runner agent API — the runner's only connection.

Every request goes to the one configured server origin. The client never
follows redirects (a redirect to another host would carry the credential
there) and refuses any download path the server hands it that is not a
relative path under ``/api/runner-agent/v1/artifacts/`` — so even a
compromised or misconfigured server cannot make the runner fetch from GitHub,
a mirror, or anywhere else.

Errors are mapped to what the agent should *do*:

  ``AuthError``      401 — credential rejected: stop, re-register. Fail closed.
  ``DisabledError``  403 — disabled on the server: heartbeat, take no work.
  ``JobGone``        404/409 — the job is not ours any more: drop it.
  ``TokenError``     410 — enrollment token used/expired: get a new one.
  ``RequestError``   400/413/422 — we sent something the server refuses.
  ``ServerError``    5xx, timeouts, connection failures — transient: retry.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from . import __version__
from .config import Config
from .protocol import DesiredTools, HeartbeatResponse, ProgressResponse, RegisterResponse

logger = logging.getLogger(__name__)

API = "/api/runner-agent/v1"
ARTIFACT_PREFIX = f"{API}/artifacts/"
_CHUNK = 1024 * 1024


class ClientError(Exception):
    def __init__(self, message: str, status: int | None = None, code: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class AuthError(ClientError):
    pass


class DisabledError(ClientError):
    pass


class JobGone(ClientError):
    pass


class TokenError(ClientError):
    pass


class RequestError(ClientError):
    pass


class ServerError(ClientError):
    pass


class ChecksumError(ClientError):
    pass


def _detail(resp: httpx.Response) -> tuple[str, str]:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:300], ""
    detail = body.get("detail") if isinstance(body, dict) else body
    if isinstance(detail, dict):
        return str(detail.get("message") or detail)[:500], str(detail.get("code") or "")
    return str(detail)[:500], ""


def _raise_for(resp: httpx.Response) -> None:
    if resp.status_code < 400:
        return
    message, code = _detail(resp)
    status = resp.status_code
    if status == 401:
        raise AuthError(message or "credential rejected", status, code)
    if status == 403:
        raise DisabledError(message or "runner disabled", status, code)
    if status in (404, 409):
        raise JobGone(message or "job not found", status, code)
    if status == 410:
        raise TokenError(message or "token used or expired", status, code)
    if status >= 500:
        raise ServerError(f"server error {status}: {message}", status, code)
    raise RequestError(f"request refused ({status}): {message}", status, code)


class ServerClient:
    def __init__(
        self,
        config: Config,
        server_url: str,
        credential: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self.server_url = server_url.rstrip("/")
        self._credential = credential
        headers = {"User-Agent": f"rotsy-runner/{__version__}"}
        if credential:
            headers["Authorization"] = f"Bearer {credential}"
        self._http = httpx.AsyncClient(
            base_url=self.server_url,
            headers=headers,
            verify=config.verify,
            follow_redirects=False,
            timeout=httpx.Timeout(30.0, read=60.0),
            transport=transport,
            trust_env=False,  # the runner talks to its server directly, never via an ambient proxy
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, *, timeout: float | None = None, **kwargs: Any) -> httpx.Response:
        if not path.startswith("/api/"):
            raise ValueError(f"refusing to call {path!r}: not a Rotsy API path")
        try:
            resp = await self._http.request(method, path, timeout=timeout or httpx.USE_CLIENT_DEFAULT, **kwargs)
        except httpx.TimeoutException as exc:
            raise ServerError(f"timed out talking to {self.server_url}: {type(exc).__name__}") from exc
        except httpx.TransportError as exc:
            raise ServerError(f"cannot reach {self.server_url}: {exc}") from exc
        if 300 <= resp.status_code < 400:
            raise RequestError(
                f"server answered with a redirect ({resp.status_code}); refusing to follow it", resp.status_code
            )
        _raise_for(resp)
        return resp

    # --- registration + heartbeat ---------------------------------------------------
    async def register(self, token: str, facts: dict[str, Any]) -> RegisterResponse:
        resp = await self._request("POST", f"{API}/register", json={"token": token, **facts})
        return RegisterResponse.model_validate(resp.json())

    async def heartbeat(self, body: dict[str, Any]) -> HeartbeatResponse:
        resp = await self._request("POST", f"{API}/heartbeat", json=body)
        return HeartbeatResponse.model_validate(resp.json())

    async def desired_tools(self) -> DesiredTools:
        resp = await self._request("GET", f"{API}/tools/desired")
        return DesiredTools.model_validate(resp.json())

    # --- jobs ------------------------------------------------------------------------
    async def claim(self, wait_seconds: int, capacity: int) -> dict[str, Any] | None:
        resp = await self._request(
            "POST",
            f"{API}/jobs/claim",
            json={"wait_seconds": wait_seconds, "capacity": capacity},
            timeout=wait_seconds + 30.0,
        )
        if resp.status_code == 204:
            return None
        return resp.json()

    async def progress(self, job_uid: str, percent: int, message: str, stage: str = "") -> ProgressResponse:
        resp = await self._request(
            "POST",
            f"{API}/jobs/{job_uid}/progress",
            json={"percent": max(0, min(100, percent)), "message": message[:500], "stage": stage[:32]},
        )
        return ProgressResponse.model_validate(resp.json())

    async def complete(self, job_uid: str, results: list[dict[str, Any]]) -> dict[str, Any]:
        resp = await self._request("POST", f"{API}/jobs/{job_uid}/complete", json={"results": results}, timeout=300.0)
        return resp.json()

    async def fail(self, job_uid: str, error: str, detail: str = "", retryable: bool = False) -> dict[str, Any]:
        resp = await self._request(
            "POST",
            f"{API}/jobs/{job_uid}/fail",
            json={"error": error[:2000] or "failed", "detail": detail[:8000], "retryable": retryable},
        )
        return resp.json()

    # --- artifacts --------------------------------------------------------------------
    async def download(
        self,
        path: str,
        dest: Path,
        *,
        expected_sha256: str,
        expected_size: int = 0,
        on_progress: Callable[[int, int], Awaitable[None]] | None = None,
    ) -> Path:
        """Fetch an artifact from the server into ``dest``, verified.

        Resumes a previous partial download (``dest.partial``) with ``Range``.
        The final file only appears at ``dest`` once its SHA-256 matches;
        a mismatch deletes the partial and raises :class:`ChecksumError`.
        """
        if not path.startswith(ARTIFACT_PREFIX) or "://" in path or ".." in path or "?" in path:
            raise RequestError(f"refusing to download {path!r}: artifacts come only from the Rotsy server")
        dest.parent.mkdir(parents=True, exist_ok=True)
        partial = dest.with_name(dest.name + ".partial")
        done = partial.stat().st_size if partial.exists() else 0
        if expected_size and done > expected_size:
            partial.unlink()
            done = 0
        headers = {"Range": f"bytes={done}-"} if done else {}
        try:
            async with self._http.stream("GET", path, headers=headers, timeout=httpx.Timeout(30.0, read=300.0)) as resp:
                if 300 <= resp.status_code < 400:
                    raise RequestError("artifact download answered with a redirect; refusing to follow it")
                if resp.status_code == 416 and done:
                    pass  # already complete; verify below
                else:
                    if resp.status_code >= 400:
                        await resp.aread()
                        _raise_for(resp)
                    if done and resp.status_code == 200:
                        done = 0  # server ignored Range; start over
                    mode = "ab" if done else "wb"
                    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | (os.O_APPEND if done else os.O_TRUNC), 0o600)
                    with os.fdopen(fd, mode) as fh:
                        async for chunk in resp.aiter_bytes(_CHUNK):
                            fh.write(chunk)
                            done += len(chunk)
                            if expected_size and done > expected_size:
                                raise ChecksumError("artifact is larger than the server said it would be")
                            if on_progress is not None:
                                await on_progress(done, expected_size)
        except httpx.TimeoutException as exc:
            raise ServerError(f"artifact download timed out ({type(exc).__name__}); will resume") from exc
        except httpx.TransportError as exc:
            raise ServerError(f"artifact download interrupted: {exc}; will resume") from exc

        actual = await asyncio.to_thread(sha256_file, partial)
        if actual != expected_sha256:
            partial.unlink(missing_ok=True)
            raise ChecksumError(f"checksum mismatch for {dest.name}: got {actual}, expected {expected_sha256}")
        os.replace(partial, dest)
        return dest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()

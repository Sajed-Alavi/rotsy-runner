"""Logging with secret redaction.

Every record passes through :class:`RedactingFilter`, which removes anything
shaped like a Rotsy secret (``rre_`` enrollment tokens, ``rrt_`` runner
credentials, ``rrj_`` job registry credentials) plus any exact values
registered with :func:`register_secret`. It runs on the formatted message and
its arguments, so a secret interpolated by a library — an httpx error echoing
a header, say — is caught too.
"""

from __future__ import annotations

import logging
import re
import sys

_PATTERN = re.compile(r"\brr[etj]_[A-Za-z0-9_-]{8,}")
_BASIC = re.compile(r"(?i)(authorization:\s*(?:basic|bearer)\s+)[A-Za-z0-9._~+/=-]+")
_secrets: set[str] = set()


def register_secret(value: str) -> None:
    if value and len(value) >= 8:
        _secrets.add(value)


def redact(text: str) -> str:
    for secret in _secrets:
        text = text.replace(secret, "***")
    text = _PATTERN.sub(lambda m: m.group(0)[:4] + "***", text)
    return _BASIC.sub(r"\1***", text)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken format string must not drop the record
            message = str(record.msg)
        record.msg = redact(message)
        record.args = ()
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def setup(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s :: %(message)s"))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # httpx logs every request line at INFO; keep it at WARNING unless debugging.
    logging.getLogger("httpx").setLevel(logging.DEBUG if level == "DEBUG" else logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

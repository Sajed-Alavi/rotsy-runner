"""Grype adapter: invoke the binary, parse its JSON report.

Moved from the Rotsy server. Registry-only by construction — the explicit
``registry:`` reference plus ``GRYPE_DEFAULT_IMAGE_PULL_SOURCE=registry`` keep
Grype off local container runtimes, which it would otherwise try first. The
database is the one the runner installed from the Rotsy server: auto-update
and update checks are off, so Grype never reaches for the Internet.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .base import (
    Credentials,
    ScanOutcome,
    assert_static_ref,
    exec_scanner,
    first_error_line,
    parse_json_report,
    redact,
    scanner_env,
    tail,
)

# Grype's "Negligible" sits below Low with no NVD equivalent; bucketing it as
# UNKNOWN would report a graded finding as ungraded. Fold it into LOW.
_SEVERITY_ALIASES = {"NEGLIGIBLE": "LOW"}


def normalise_severity(value: str | None) -> str:
    raw = (value or "UNKNOWN").upper()
    return _SEVERITY_ALIASES.get(raw, raw)


def highest_cvss(match: dict[str, Any]) -> float:
    """The highest CVSS base score across every related vulnerability entry."""
    best = 0.0
    for related in match.get("relatedVulnerabilities") or []:
        for score in related.get("cvss") or []:
            try:
                best = max(best, float((score.get("metrics") or {}).get("baseScore") or score.get("score") or 0))
            except (TypeError, ValueError):
                continue
    return best


def parse(raw: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in raw.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        fixed = (vuln.get("fix") or {}).get("versions") or []
        findings.append(
            {
                "cve": vuln.get("id") or "UNKNOWN",
                "severity": normalise_severity(vuln.get("severity")),
                "package": artifact.get("name") or "",
                "installed_version": artifact.get("version") or "",
                "fixed_version": fixed[0] if fixed else "",
                "title": (vuln.get("description") or "")[:200],
                "cvss": highest_cvss(match),
            }
        )
    return findings


def db_env(db_dir: Path) -> dict[str, str]:
    """The Grype settings that pin it to the locally installed database."""
    return {
        "GRYPE_DB_CACHE_DIR": str(db_dir),
        "GRYPE_DB_AUTO_UPDATE": "false",
        # A slightly stale database beats no scan; the server shows its age.
        "GRYPE_DB_VALIDATE_AGE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    }


def build(binary: str, db_dir: Path, image_ref: str, creds: Credentials, *, insecure: bool) -> tuple[list, dict]:
    args = [binary, f"registry:{image_ref}", "-o", "json"]
    env = scanner_env(
        {
            "GRYPE_REGISTRY_AUTH_USERNAME": creds.username,
            "GRYPE_REGISTRY_AUTH_PASSWORD": creds.password,
            "GRYPE_DEFAULT_IMAGE_PULL_SOURCE": "registry",
            **db_env(db_dir),
        }
    )
    if insecure:
        env["GRYPE_REGISTRY_INSECURE_USE_HTTP"] = "true"
        env["GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY"] = "true"
    return args, env


async def run(
    binary: str,
    db_dir: Path,
    image_ref: str,
    creds: Credentials,
    *,
    insecure: bool,
    timeout: float,
    tool_version: str = "",
    db_version: str = "",
) -> ScanOutcome:
    """Scan ``image_ref`` with Grype, reading it from the registry only."""
    assert_static_ref(image_ref)
    args, env = build(binary, db_dir, image_ref, creds, insecure=insecure)
    shown = redact(args, [creds.password])
    started = time.monotonic()
    try:
        code, stdout, stderr = await exec_scanner(args, env, timeout)
    except TimeoutError as exc:
        return ScanOutcome(
            "grype",
            False,
            error=str(exc),
            detail=f"$ {shown}",
            duration_ms=int((time.monotonic() - started) * 1000),
            tool_version=tool_version,
        )
    elapsed = int((time.monotonic() - started) * 1000)
    detail = redact([f"$ {shown}\nexit {code}\n{tail(stderr or stdout)}"], [creds.password])
    common = {"detail": detail, "duration_ms": elapsed, "tool_version": tool_version, "db_version": db_version}
    if code != 0:
        return ScanOutcome("grype", False, error=first_error_line(stderr) or f"grype exited {code}", **common)
    try:
        raw = parse_json_report(stdout)
    except json.JSONDecodeError as exc:
        return ScanOutcome("grype", False, error=f"could not parse grype JSON output: {exc}", **common)
    return ScanOutcome("grype", True, parse(raw), **common)

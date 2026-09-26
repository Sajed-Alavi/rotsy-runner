"""What the runner tells the server about itself: metrics and events.

The server cannot reach a runner (runners dial out; nothing dials in), so
everything the Runners page shows is *pushed*: a metrics snapshot and a batch
of events ride on every heartbeat — only once the server has said it accepts
them (``features`` in the heartbeat response), so a newer runner keeps working
against an older server.

* :class:`SystemSampler` reads ``/proc`` and cgroup v2 directly — no extra
  dependency. Inside a container, CPU and memory are the container's own
  (cgroup) figures, which is what "how loaded is this runner" means; on a
  bare host they are the host's. Anything unreadable is reported as ``None``
  rather than guessed.
* :class:`Telemetry` keeps the counters (jobs, per-scanner results and
  durations, heartbeats, tool syncs) and a bounded event buffer. Events that
  could not be delivered are put back and sent with the next heartbeat.
"""

from __future__ import annotations

import os
import shutil
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CGROUP = Path("/sys/fs/cgroup")
EVENT_BUFFER = 500
EVENTS_PER_HEARTBEAT = 100
_DIR_SIZE_EVERY = 600.0


def _read(path: Path) -> str | None:
    try:
        return path.read_text()
    except OSError:
        return None


def _int(text: str | None) -> int | None:
    try:
        return int(text.strip()) if text is not None else None
    except ValueError:
        return None


def _kv(text: str | None) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                out[parts[0].rstrip(":")] = int(parts[1])
            except ValueError:
                continue
    return out


def available_cores() -> float:
    """Cores this process may use: the cgroup CPU quota, else the affinity mask."""
    quota = _read(CGROUP / "cpu.max")
    if quota:
        limit, _, period = quota.strip().partition(" ")
        if limit != "max" and period:
            try:
                return max(0.01, int(limit) / int(period))
            except (ValueError, ZeroDivisionError):
                pass
    try:
        return float(len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return float(os.cpu_count() or 1)


def dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                continue
    return total


class SystemSampler:
    """Point-in-time system figures, with rates computed between calls."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self._cpu_prev: tuple[float, float] | None = None  # (usage seconds, wall seconds)
        self._host_cpu_prev: tuple[int, int] | None = None  # (busy jiffies, total jiffies)
        self._net_prev: tuple[float, int, int] | None = None
        self._dir_sizes: dict[str, int] = {}
        self._dir_sizes_at = 0.0

    # --- CPU ---------------------------------------------------------------------
    def cpu(self) -> tuple[float | None, str]:
        stat = _kv(_read(CGROUP / "cpu.stat"))
        now = time.monotonic()
        if "usage_usec" in stat:
            usage = stat["usage_usec"] / 1e6
            prev, self._cpu_prev = self._cpu_prev, (usage, now)
            if prev is None or now <= prev[1]:
                return None, "cgroup"
            share = (usage - prev[0]) / ((now - prev[1]) * available_cores())
            return round(min(100.0, max(0.0, share * 100)), 1), "cgroup"
        line = (_read(Path("/proc/stat")) or "").split("\n", 1)[0].split()
        if len(line) < 5 or line[0] != "cpu":
            return None, "host"
        values = [int(v) for v in line[1:9] if v.isdigit()]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        prev_host, self._host_cpu_prev = self._host_cpu_prev, (total - idle, total)
        if prev_host is None or total <= prev_host[1]:
            return None, "host"
        share = ((total - idle) - prev_host[0]) / (total - prev_host[1])
        return round(min(100.0, max(0.0, share * 100)), 1), "host"

    # --- memory ------------------------------------------------------------------
    @staticmethod
    def memory() -> tuple[int | None, int | None, str]:
        meminfo = _kv(_read(Path("/proc/meminfo")))
        host_total = meminfo.get("MemTotal", 0) * 1024 or None
        current = _int(_read(CGROUP / "memory.current"))
        if current is not None:
            limit_text = (_read(CGROUP / "memory.max") or "max").strip()
            limit = _int(limit_text) if limit_text != "max" else None
            # Page cache the kernel can drop is not pressure (docker stats does the same).
            inactive = _kv(_read(CGROUP / "memory.stat")).get("inactive_file", 0)
            total = min(limit, host_total) if (limit and host_total) else (limit or host_total)
            return max(0, current - inactive), total, "cgroup"
        if host_total and "MemAvailable" in meminfo:
            return host_total - meminfo["MemAvailable"] * 1024, host_total, "host"
        return None, host_total, "host"

    # --- network -----------------------------------------------------------------
    def network(self) -> tuple[float | None, float | None]:
        rx = tx = 0
        for line in (_read(Path("/proc/net/dev")) or "").splitlines()[2:]:
            name, _, rest = line.partition(":")
            fields = rest.split()
            if name.strip() == "lo" or len(fields) < 9:
                continue
            rx += int(fields[0])
            tx += int(fields[8])
        now = time.monotonic()
        prev, self._net_prev = self._net_prev, (now, rx, tx)
        if prev is None or now <= prev[0] or rx < prev[1] or tx < prev[2]:
            return None, None
        elapsed = now - prev[0]
        return round((rx - prev[1]) / elapsed, 1), round((tx - prev[2]) / elapsed, 1)

    # --- disk --------------------------------------------------------------------
    def disk(self) -> tuple[int | None, int | None]:
        try:
            usage = shutil.disk_usage(self.data_dir)
        except OSError:
            return None, None
        return usage.total - usage.free, usage.total

    def refresh_dir_sizes(self, force: bool = False) -> None:
        """Size of the tools and cache directories — slow, so at most every 10 min."""
        now = time.monotonic()
        if not force and self._dir_sizes and now - self._dir_sizes_at < _DIR_SIZE_EVERY:
            return
        self._dir_sizes = {name: dir_size(self.data_dir / name) for name in ("tools", "cache", "downloads")}
        self._dir_sizes_at = now

    # --- process -----------------------------------------------------------------
    @staticmethod
    def process_rss() -> int | None:
        kb = _kv(_read(Path("/proc/self/status"))).get("VmRSS")
        return kb * 1024 if kb is not None else None

    @staticmethod
    def host_uptime() -> int | None:
        text = _read(Path("/proc/uptime"))
        try:
            return int(float(text.split()[0])) if text else None
        except (ValueError, IndexError):
            return None

    def sample(self) -> dict[str, Any]:
        cpu, cpu_scope = self.cpu()
        mem_used, mem_total, mem_scope = self.memory()
        rx, tx = self.network()
        disk_used, disk_total = self.disk()
        try:
            load = os.getloadavg()
        except OSError:
            load = (None, None, None)
        return {
            "cpu_percent": cpu,
            "cpu_cores": round(available_cores(), 2),
            "cpu_scope": cpu_scope,
            "load_1": round(load[0], 2) if load[0] is not None else None,
            "load_5": round(load[1], 2) if load[1] is not None else None,
            "load_15": round(load[2], 2) if load[2] is not None else None,
            "memory_used_bytes": mem_used,
            "memory_total_bytes": mem_total,
            "memory_scope": mem_scope,
            "disk_used_bytes": disk_used,
            "disk_total_bytes": disk_total,
            "tools_bytes": self._dir_sizes.get("tools"),
            "cache_bytes": self._dir_sizes.get("cache"),
            "net_rx_bps": rx,
            "net_tx_bps": tx,
            "process_rss_bytes": self.process_rss(),
            "host_uptime_seconds": self.host_uptime(),
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Telemetry:
    """Counters and events since the agent started."""

    def __init__(self, data_dir: Path) -> None:
        self.system = SystemSampler(data_dir)
        self.started = time.monotonic()
        self.jobs = {"completed": 0, "failed": 0, "cancelled": 0, "handed_back": 0, "refused": 0}
        self.scanners: dict[str, dict[str, Any]] = {}
        self.heartbeat_rtt_ms: float | None = None
        self.heartbeat_failures = 0
        self.reconnects = 0
        self.tool_syncs = {"ok": 0, "failed": 0}
        self.last_sync_at: str | None = None
        self._events: deque[dict[str, Any]] = deque(maxlen=EVENT_BUFFER)
        self.dropped_events = 0

    # --- events ------------------------------------------------------------------
    def event(self, kind: str, message: str, *, level: str = "info", job_uid: str | None = None) -> None:
        if len(self._events) == self._events.maxlen:
            self.dropped_events += 1
        entry: dict[str, Any] = {"at": _now_iso(), "level": level, "kind": kind, "message": message[:500]}
        if job_uid:
            entry["job_uid"] = job_uid[:64]
        self._events.append(entry)

    def drain_events(self, limit: int = EVENTS_PER_HEARTBEAT) -> list[dict[str, Any]]:
        batch = []
        while self._events and len(batch) < limit:
            batch.append(self._events.popleft())
        return batch

    def restore_events(self, batch: list[dict[str, Any]]) -> None:
        """Put back events a failed heartbeat did not deliver (oldest first)."""
        for entry in reversed(batch):
            if len(self._events) == self._events.maxlen:
                self.dropped_events += 1
                continue
            self._events.appendleft(entry)

    @property
    def pending_events(self) -> int:
        return len(self._events)

    # --- counters ----------------------------------------------------------------
    def job_finished(self, status: str) -> None:
        if status in self.jobs:
            self.jobs[status] += 1

    def scan_result(self, scanner: str, ok: bool, duration_ms: int, findings: int) -> None:
        stats = self.scanners.setdefault(
            scanner, {"ok": 0, "failed": 0, "last_duration_ms": 0, "durations": deque(maxlen=50), "findings": 0}
        )
        stats["ok" if ok else "failed"] += 1
        stats["last_duration_ms"] = duration_ms
        stats["durations"].append(duration_ms)
        stats["findings"] = findings

    def heartbeat_ok(self, rtt_ms: float) -> None:
        if self.heartbeat_failures:
            self.reconnects += 1
        self.heartbeat_failures = 0
        self.heartbeat_rtt_ms = round(rtt_ms, 1)

    def heartbeat_failed(self) -> None:
        self.heartbeat_failures += 1

    def sync_done(self, ok: bool) -> None:
        self.tool_syncs["ok" if ok else "failed"] += 1
        self.last_sync_at = _now_iso()

    def snapshot(self, running_jobs: int) -> dict[str, Any]:
        scanners = {}
        for name, stats in self.scanners.items():
            durations = list(stats["durations"])
            scanners[name] = {
                "ok": stats["ok"],
                "failed": stats["failed"],
                "last_duration_ms": stats["last_duration_ms"],
                "avg_duration_ms": int(sum(durations) / len(durations)) if durations else 0,
                "last_findings": stats["findings"],
            }
        return {
            **self.system.sample(),
            "uptime_seconds": int(time.monotonic() - self.started),
            "jobs_running": running_jobs,
            "jobs_completed": self.jobs["completed"],
            "jobs_failed": self.jobs["failed"],
            "jobs_cancelled": self.jobs["cancelled"],
            "jobs_handed_back": self.jobs["handed_back"],
            "scanners": scanners,
            "heartbeat_rtt_ms": self.heartbeat_rtt_ms,
            "heartbeat_failures": self.heartbeat_failures,
            "reconnects": self.reconnects,
            "tool_syncs_ok": self.tool_syncs["ok"],
            "tool_syncs_failed": self.tool_syncs["failed"],
            "last_tool_sync_at": self.last_sync_at,
            "events_dropped": self.dropped_events,
        }

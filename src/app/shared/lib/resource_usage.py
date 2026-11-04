"""Host and container resource usage, for the header monitor.

Deliberately dependency-free: the numbers come from `/proc`, cgroup v2 and
`shutil.disk_usage`, so nothing has to be installed and nothing has to be sampled by a
background thread. CPU percentage is computed from the delta between two `/proc/stat`
reads, which the monitor's own polling interval supplies — a single read can only tell
you cumulative jiffies, and reporting load average as "CPU %" would be a lie.

Every read is defensive: this runs on Linux in production and on macOS during
development, and a monitor that throws is worse than one that says "unavailable".
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

PROC_STAT = Path("/proc/stat")
PROC_MEMINFO = Path("/proc/meminfo")
PROC_LOADAVG = Path("/proc/loadavg")
PROC_UPTIME = Path("/proc/uptime")
CGROUP_MEMORY_CURRENT = Path("/sys/fs/cgroup/memory.current")
CGROUP_MEMORY_MAX = Path("/sys/fs/cgroup/memory.max")
CGROUP_CPU_MAX = Path("/sys/fs/cgroup/cpu.max")

#: Previous /proc/stat sample, so consecutive polls can report a real percentage.
_last_cpu_sample: Optional[tuple[int, int]] = None


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text()
    except OSError:
        return None


def _cpu_times() -> Optional[tuple[int, int]]:
    """(busy, total) jiffies from /proc/stat."""
    raw = _read_text(PROC_STAT)
    if not raw:
        return None
    for line in raw.splitlines():
        if not line.startswith("cpu "):
            continue
        parts = [int(value) for value in line.split()[1:] if value.isdigit()]
        if len(parts) < 4:
            return None
        idle = parts[3] + (parts[4] if len(parts) > 4 else 0)  # idle + iowait
        total = sum(parts)
        return total - idle, total
    return None


def cpu_percent() -> Optional[float]:
    """Busy percentage since the previous call; None on the first call or non-Linux."""
    global _last_cpu_sample
    current = _cpu_times()
    if current is None:
        return None
    if _last_cpu_sample is None:
        _last_cpu_sample = current
        return None
    previous_busy, previous_total = _last_cpu_sample
    _last_cpu_sample = current
    busy, total = current
    delta_total = total - previous_total
    if delta_total <= 0:
        return None
    delta_busy = busy - previous_busy
    return round(max(0.0, min(100.0, delta_busy / delta_total * 100)), 1)


def load_average() -> dict[str, Optional[float]]:
    raw = _read_text(PROC_LOADAVG)
    if not raw:
        try:
            return {"1m": round(os.getloadavg()[0], 2), "5m": round(os.getloadavg()[1], 2), "15m": round(os.getloadavg()[2], 2)}
        except (OSError, AttributeError):
            return {"1m": None, "5m": None, "15m": None}
    parts = raw.split()
    try:
        return {"1m": float(parts[0]), "5m": float(parts[1]), "15m": float(parts[2])}
    except (IndexError, ValueError):
        return {"1m": None, "5m": None, "15m": None}


def _meminfo() -> dict[str, int]:
    raw = _read_text(PROC_MEMINFO) or ""
    values: dict[str, int] = {}
    for line in raw.splitlines():
        key, _, rest = line.partition(":")
        digits = rest.strip().split()
        if digits and digits[0].isdigit():
            values[key.strip()] = int(digits[0])  # kB
    return values


def memory() -> dict[str, Any]:
    """Host memory, plus this container's own usage and limit when cgroup v2 is there."""
    info = _meminfo()
    total_kb = info.get("MemTotal")
    available_kb = info.get("MemAvailable")
    host: dict[str, Any] = {"total_mb": None, "used_mb": None, "percent": None}
    if total_kb and available_kb:
        used_kb = total_kb - available_kb
        host = {
            "total_mb": round(total_kb / 1024),
            "used_mb": round(used_kb / 1024),
            "percent": round(used_kb / total_kb * 100, 1),
        }

    container: dict[str, Any] = {"used_mb": None, "limit_mb": None, "percent": None}
    current = _read_text(CGROUP_MEMORY_CURRENT)
    limit_raw = _read_text(CGROUP_MEMORY_MAX)
    if current and limit_raw:
        used = int(current.strip())
        limit_text = limit_raw.strip()
        # "max" means the container has no memory limit of its own.
        limit = int(limit_text) if limit_text.isdigit() else 0
        container["used_mb"] = round(used / (1024 * 1024))
        if limit:
            container["limit_mb"] = round(limit / (1024 * 1024))
            container["percent"] = round(used / limit * 100, 1)
    return {"host": host, "container": container}


def cpu_limit() -> dict[str, Any]:
    """Cores available to this container (cgroup quota), falling back to the host."""
    cores = os.cpu_count() or 1
    raw = _read_text(CGROUP_CPU_MAX)
    if raw:
        parts = raw.split()
        try:
            quota, period = int(parts[0]), int(parts[1])
            if quota > 0 and period > 0:
                allowed = quota / period
                return {"cores": round(allowed, 2), "host_cores": cores}
        except (IndexError, ValueError):
            pass
    return {"cores": cores, "host_cores": cores}


def disk(path: str = "/") -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return {"total_gb": None, "used_gb": None, "free_gb": None, "percent": None}
    return {
        "total_gb": round(usage.total / 1024**3, 1),
        "used_gb": round(usage.used / 1024**3, 1),
        "free_gb": round(usage.free / 1024**3, 1),
        "percent": round(usage.used / usage.total * 100, 1) if usage.total else None,
    }


def uptime_seconds() -> Optional[int]:
    raw = _read_text(PROC_UPTIME)
    if not raw:
        return None
    try:
        return int(float(raw.split()[0]))
    except (IndexError, ValueError):
        return None


def snapshot() -> dict[str, Any]:
    """Everything the header monitor shows, in one cheap call."""
    started = time.perf_counter()
    payload = {
        "cpu": {
            "percent": cpu_percent(),
            "load": load_average(),
            **cpu_limit(),
        },
        "memory": memory(),
        "disk": disk(),
        "uptime_seconds": uptime_seconds(),
        "collected_ms": None,
    }
    payload["collected_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return payload

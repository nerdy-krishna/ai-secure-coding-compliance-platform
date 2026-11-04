"""Reading host usage without a dependency, and without lying about gaps."""

from __future__ import annotations

from app.shared.lib import resource_usage


def test_cpu_percent_needs_two_samples(monkeypatch):
    """A single /proc/stat read only holds cumulative jiffies; the second gives a delta."""
    samples = iter(
        [
            "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\n",
            "cpu  150 0 150 900 0 0 0 0 0 0\ncpu0 75 0 75 450 0 0 0 0 0 0\n",
        ]
    )
    monkeypatch.setattr(resource_usage, "_read_text", lambda path: next(samples))
    monkeypatch.setattr(resource_usage, "_last_cpu_sample", None)

    assert resource_usage.cpu_percent() is None, "the first call has nothing to compare"
    # busy 100 → 200, total 1000 → 1200: half the new time was busy.
    assert resource_usage.cpu_percent() == 50.0


def test_memory_reads_host_and_container(monkeypatch, tmp_path):
    files = {
        "/proc/meminfo": "MemTotal:       8000000 kB\nMemAvailable:   2000000 kB\n",
        "/sys/fs/cgroup/memory.current": str(512 * 1024 * 1024),
        "/sys/fs/cgroup/memory.max": str(2 * 1024 * 1024 * 1024),
    }
    monkeypatch.setattr(resource_usage, "_read_text", lambda path: files.get(str(path)))

    payload = resource_usage.memory()

    assert payload["host"]["total_mb"] == 7812
    assert payload["host"]["used_mb"] == 5859
    assert round(payload["host"]["percent"]) == 75
    assert payload["container"]["used_mb"] == 512
    assert payload["container"]["limit_mb"] == 2048
    assert payload["container"]["percent"] == 25.0


def test_container_without_a_limit_says_so(monkeypatch):
    files = {
        "/proc/meminfo": "MemTotal:       1000000 kB\nMemAvailable:    500000 kB\n",
        "/sys/fs/cgroup/memory.current": str(100 * 1024 * 1024),
        "/sys/fs/cgroup/memory.max": "max",
    }
    monkeypatch.setattr(resource_usage, "_read_text", lambda path: files.get(str(path)))

    payload = resource_usage.memory()

    assert payload["container"]["used_mb"] == 100
    assert payload["container"]["limit_mb"] is None
    assert payload["container"]["percent"] is None


def test_unreadable_proc_yields_nulls_not_zeros(monkeypatch):
    """A monitor that reports 0% on a non-Linux host is worse than one that says nothing."""
    monkeypatch.setattr(resource_usage, "_read_text", lambda path: None)

    payload = resource_usage.snapshot()

    assert payload["cpu"]["percent"] is None
    assert payload["memory"]["host"]["total_mb"] is None
    assert payload["memory"]["host"]["percent"] is None


def test_snapshot_reports_how_long_it_took():
    payload = resource_usage.snapshot()

    assert payload["collected_ms"] is not None
    assert payload["collected_ms"] >= 0
    assert set(payload) >= {"cpu", "memory", "disk", "uptime_seconds"}


def test_cpu_limit_reads_the_cgroup_quota(monkeypatch):
    monkeypatch.setattr(
        resource_usage, "_read_text", lambda path: "200000 100000\n"
    )

    limit = resource_usage.cpu_limit()

    assert limit["cores"] == 2
    assert limit["host_cores"] >= 1


def test_disk_reports_null_when_the_path_is_missing():
    payload = resource_usage.disk("/definitely/not/here")

    assert payload["percent"] is None

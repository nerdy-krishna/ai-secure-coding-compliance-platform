"""Bulk asset import: what gets created, what is skipped, what is rejected.

An inventory starts from a spreadsheet, not from a modal. Two behaviours matter more than
the parsing: a duplicate is skipped rather than overwriting an existing authorised asset,
and a bad row is named with its line number instead of aborting the import.
"""

from __future__ import annotations

import asyncio
import csv
import io

from app.assets import importer


def test_template_has_the_columns_the_importer_reads():
    rows = list(csv.reader(io.StringIO(importer.template_csv())))

    assert rows[0] == list(importer.TEMPLATE_COLUMNS)
    assert rows[1][0].startswith("<"), "the example row must be ignored by the importer"


def csv_bytes(*rows: list[str], headers: tuple[str, ...] = importer.TEMPLATE_COLUMNS) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue().encode()


class FakeSession:
    """Just enough session for the duplicate-name lookup."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def scalars(self, *_args, **_kwargs):
        return []


def test_the_template_example_row_is_not_imported(monkeypatch):
    def no_session():
        raise AssertionError("no database needed for a file with only the example row")

    monkeypatch.setattr(importer, "AsyncSessionLocal", no_session)

    result = asyncio.run(importer.import_csv(None, csv_bytes(list(importer.EXAMPLE_ROW))))

    assert result["total"] == 0
    assert result["created"] == 0


def test_a_missing_name_column_is_reported_before_anything_is_created(monkeypatch):
    async def no_session():
        raise AssertionError("must fail on the header, not on the database")

    monkeypatch.setattr(importer, "AsyncSessionLocal", no_session)

    result = asyncio.run(
        importer.import_csv(None, csv_bytes(["x"], headers=("asset", "kind")))
    )

    assert "name" in result["error"]


def test_a_non_utf8_file_is_reported_plainly():
    result = asyncio.run(importer.import_csv(None, b"\xff\xfe\x00bad"))

    assert "UTF-8" in result["error"]


def test_bad_rows_are_rejected_with_their_line_and_reason(monkeypatch):
    """Validation happens before any asset is created, per row."""
    monkeypatch.setattr(importer, "AsyncSessionLocal", lambda: FakeSession())
    content = csv_bytes(
        ["", "web_app", "", "", "", "", "", "", "", "", ""],  # line 2: no name
        ["edge", "spaceship", "", "", "", "", "", "", "", "", ""],  # line 3: bad kind
        ["edge2", "host", "", "", "10.0.0.9", "not-a-port", "https", "", "", "", ""],  # line 4
    )

    result = asyncio.run(importer.import_csv("00000000-0000-0000-0000-000000000000", content))

    reasons = {row["line"]: row["reason"] for row in result["rejected_rows"]}
    assert "missing name" in reasons[2]
    assert "unknown kind" in reasons[3]
    assert "not a number" in reasons[4]


def test_port_parsing_accepts_ranges_and_rejects_nonsense():
    assert importer._parse_port("443") == (443, None)
    assert importer._parse_port("") == (None, None)
    assert importer._parse_port("0")[1] is not None
    assert importer._parse_port("70000")[1] is not None
    assert importer._parse_port("http")[1] is not None


def test_summary_counts_add_up():
    summary = importer.ImportSummary(total=5, created=[{}, {}], duplicates=["a"], rejected=[{}])

    payload = summary.as_dict()

    assert payload["total"] == 5
    assert payload["created"] == 2 and payload["duplicates"] == 1 and payload["rejected"] == 1


def test_a_sweep_is_a_probe_then_a_check(monkeypatch):
    """One implementation of "find out what this asset is", used by both paths."""
    import asyncio
    import inspect
    import uuid

    from app.assets import sweep
    from app.assets import service

    source = inspect.getsource(sweep.run_sweep)
    assert "probe_inventory" in source and "rescan=True" in source
    assert "check_cves" in source
    # The divergent fingerprinter is gone: the sweep no longer carries its own.
    assert not hasattr(sweep, "fingerprint_services")

    calls: list[str] = []

    async def fake_probe(**kwargs):
        calls.append("probe")
        assert kwargs["rescan"] is True
        return {"endpoints_probed": 3, "fingerprints_found": 1, "queued": 0}

    async def fake_check(**kwargs):
        calls.append("check")
        return {"matched": 2, "applicable": 0, "undetermined": 2, "verified": 0,
                "verification_errors": 0, "not_applicable": 0}

    monkeypatch.setattr(service, "probe_inventory", fake_probe)
    monkeypatch.setattr(service, "check_cves", fake_check)

    outcome = asyncio.run(sweep.run_sweep(tenant_id=uuid.uuid4()))

    assert calls == ["probe", "check"], "a sweep probes first, then checks"
    assert outcome["fingerprints_found"] == 1
    assert outcome["matched"] == 2

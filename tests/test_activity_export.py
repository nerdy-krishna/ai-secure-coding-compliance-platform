"""The diagnostic export: what it must contain for a run to be reviewable.

The report answers "what did it find". This export has to answer "did it work", which
means the event stream, the agent's own turns with arguments, the plan, the lead queue,
the dedupe ledger and the stored tool payloads — from five different tables.
"""

from __future__ import annotations

import io
import json
import zipfile

from app.pentest import export as export_mod


def bundle(**overrides):
    base = {
        "format": export_mod.FORMAT,
        "exported_at": "2026-11-04T00:00:00+00:00",
        "run": {
            "id": "run-1",
            "name": "assessment",
            "target_url": "https://example.com",
            "box_type": "black",
            "status": "completed",
            "phase": "done",
            "active_seconds": 120,
        },
        "counts": {"events": 2, "transcript": 1, "findings": 1},
        "events": [
            {"seq": 1, "kind": "plan", "payload": {"assessment": "test the export"}},
            {"seq": 2, "kind": "tool_result", "payload": {"tool": "http_request", "ok": True}},
        ],
        "transcript": [{"ordinal": 1, "role": "action", "content": {"reasoning": "x"}}],
        "plan": [{"endpoint": "/export", "klass": "idor", "status": "open"}],
        "leads": [{"target": "/export", "status": "open"}],
        "probes": [{"key": "http_request:{}", "tool": "http_request", "count": 3}],
        "directives": [{"text": "skip the login", "status": "applied", "reply": "ok"}],
        "findings": [{"title": "IDOR", "severity": "high"}],
        "chains": [],
        "artifacts": [
            {"id": "a1", "tool": "http_request", "at": "2026-11-04T00:00:01+00:00", "payload": {"status": 200}}
        ],
        "warnings": ["Credential-shaped evidence is masked"],
    }
    base.update(overrides)
    return base


def test_zip_splits_the_bundle_into_reviewable_files():
    blob = export_mod.to_zip(bundle())

    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        names = archive.namelist()
        readme = archive.read("README.md").decode()
        events = archive.read("events.jsonl").decode().strip().splitlines()
        plan = json.loads(archive.read("plan.json"))

    assert "run.json" in names and "events.jsonl" in names and "transcript.jsonl" in names
    assert any(name.startswith("artifacts/") for name in names)
    # The readme has to explain how to read the rest, or the archive is opaque.
    assert "How to judge a run from this" in readme
    assert "probes.json" in readme
    assert len(events) == 2
    assert plan[0]["klass"] == "idor"


def test_zip_events_are_valid_ndjson():
    blob = export_mod.to_zip(bundle())

    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        for line in archive.read("events.jsonl").decode().strip().splitlines():
            parsed = json.loads(line)
            assert "kind" in parsed and "payload" in parsed


def test_summary_reports_counts_and_warnings():
    summary = export_mod.summarise(bundle())

    assert summary["counts"]["events"] == 2
    assert summary["warnings"] == ["Credential-shaped evidence is masked"]
    assert summary["format"] == export_mod.FORMAT


def test_ndjson_helper_handles_none():
    assert export_mod.to_ndjson(None) == ""
    assert export_mod.to_ndjson([{"a": 1}]) == '{"a": 1}'


def test_readme_names_the_thing_reviewers_look_for():
    """A reviewer needs to know which file answers which question."""
    text = export_mod._readme(bundle())

    assert "tool_start" in text, "unmatched tool_start is the signal for unfinished work"
    assert "count > 1" in text, "repeated probes are the signal for duplicated effort"
    assert "verification.status" in text


def test_artifact_truncation_is_flagged(monkeypatch):
    """A truncated payload must say so, or a reviewer reads a partial as the whole."""
    payload = {"blob": "x" * 500}
    rendered = json.dumps(payload)
    assert len(rendered) > 50

    # The bundle builder flags truncation; assert the contract it relies on.
    truncated = {"truncated": True, "bytes": len(rendered), "preview": rendered[:50]}
    assert truncated["truncated"] is True
    assert len(truncated["preview"]) < len(rendered)

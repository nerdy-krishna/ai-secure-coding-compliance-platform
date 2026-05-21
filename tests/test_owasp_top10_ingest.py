"""Unit tests for the OWASP Top-10 JSON ingest path (§3.11).

`SecurityStandardsService.ingest_owasp_top10_json` is shared by both
the LLM Top-10 and Agentic Top-10 ingest endpoints. These tests pin:

- Doc-text formatting matches the regex anchors that the
  `generic_specialized_agent._extract_patterns_from_doc` extractor
  uses (`**Vulnerability Pattern (..):**`, `[[<LANG> PATTERNS]]`,
  `Vulnerable: ` / `Secure: ` blocks).
- Metadata carries the expected `framework_name` + `control_family`
  + `scan_ready=True` so the agent's `metadata_filter` retrieves
  only the right framework's entries during a scan.
- Mismatched `framework` / `control_family` in the upload JSON is
  rejected with HTTP 400 (defense against an operator uploading the
  LLM JSON to the agentic endpoint or vice versa).
"""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException, UploadFile

from app.core.services.security_standards_service import SecurityStandardsService


def _make_service(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[SecurityStandardsService, MagicMock]:
    """SecurityStandardsService with a stubbed RAG service."""
    fake_rag = MagicMock()
    fake_rag.delete_by_framework = MagicMock()
    fake_rag.add = MagicMock()
    monkeypatch.setattr(
        "app.core.services.security_standards_service.get_rag_service",
        lambda: fake_rag,
    )
    return SecurityStandardsService(job_repo=None, llm_config_repo=None), fake_rag


def _upload(name: str, payload: dict) -> UploadFile:
    body = json.dumps(payload).encode("utf-8")
    f = UploadFile(filename=name, file=io.BytesIO(body))
    return f


def _entry(eid: str = "LLM01") -> dict:
    return {
        "id": eid,
        "title": "Prompt Injection",
        "description": "Adversarial input alters model behavior.",
        "vulnerability_pattern": "Untrusted input concatenated as instructions.",
        "secure_pattern": "Wrap untrusted content in delimiters.",
        "examples": {
            "python": {
                "vulnerable": "prompt = f'Sys: {user_input}'",
                "secure": "prompt = f'<data>\\n{user_input}\\n</data>'",
            }
        },
        "cwes": ["CWE-77", "CWE-94"],
    }


def test_format_owasp_top10_doc_emits_agent_extractor_anchors() -> None:
    """The generated doc_text must match what
    `_extract_patterns_from_doc` parses, otherwise the RAG context the
    agent receives at scan time will be empty (silent failure)."""
    entry = _entry("LLM01")
    entry["control_family"] = "LLM Security"
    doc = SecurityStandardsService._format_owasp_top10_doc(entry)

    # Vulnerability + Secure pattern headers (regex-matched by the agent).
    assert "**Vulnerability Pattern (LLM01 - Prompt Injection):**" in doc
    assert "**Secure Pattern (LLM01 - Prompt Injection):**" in doc

    # Language-specific block (regex-matched by the agent).
    assert "[[PYTHON PATTERNS]]" in doc
    assert "Vulnerable:" in doc and "Secure:" in doc
    assert "```python" in doc

    # Metadata in body for human readers.
    assert "[LLM Security]: Prompt Injection" in doc
    assert "Related CWEs: CWE-77, CWE-94" in doc


@pytest.mark.asyncio
async def test_ingest_llm_top10_writes_correct_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, fake_rag = _make_service(monkeypatch)
    upload = _upload(
        "llm.json",
        {
            "framework": "llm_top10",
            "control_family": "LLM Security",
            "version": "2025",
            "source": "OWASP Top 10 for LLM Apps",
            "entries": [_entry("LLM01"), _entry("LLM02")],
        },
    )

    result = await service.ingest_owasp_top10_json(
        upload,
        framework_name="llm_top10",
        expected_control_family="LLM Security",
        user_id=1,
    )

    assert result["count"] == 2
    fake_rag.delete_by_framework.assert_called_once_with("llm_top10")
    fake_rag.add.assert_called_once()
    call = fake_rag.add.call_args
    metas = call.kwargs["metadatas"]
    assert all(m["framework_name"] == "llm_top10" for m in metas)
    assert all(m["control_family"] == "LLM Security" for m in metas)
    assert all(m["scan_ready"] is True for m in metas)
    assert call.kwargs["ids"] == ["llm_top10-LLM01", "llm_top10-LLM02"]


@pytest.mark.asyncio
async def test_ingest_rejects_wrong_framework_in_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Uploading the agentic JSON to the llm_top10 endpoint must 400."""
    service, _ = _make_service(monkeypatch)
    upload = _upload(
        "agentic.json",
        {
            "framework": "agentic_top10",  # wrong framework for this slot
            "control_family": "Agentic Security",
            "entries": [_entry("AGENT01")],
        },
    )
    with pytest.raises(HTTPException) as exc_info:
        await service.ingest_owasp_top10_json(
            upload,
            framework_name="llm_top10",
            expected_control_family="LLM Security",
            user_id=1,
        )
    assert exc_info.value.status_code == 400
    assert "framework" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_ingest_rejects_wrong_control_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _ = _make_service(monkeypatch)
    upload = _upload(
        "llm.json",
        {
            "framework": "llm_top10",
            "control_family": "Wrong Family",  # mismatch
            "entries": [_entry("LLM01")],
        },
    )
    with pytest.raises(HTTPException) as exc_info:
        await service.ingest_owasp_top10_json(
            upload,
            framework_name="llm_top10",
            expected_control_family="LLM Security",
            user_id=1,
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_ingest_rejects_non_json_upload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _ = _make_service(monkeypatch)
    upload = UploadFile(filename="not_json.csv", file=io.BytesIO(b"id,title\n"))
    with pytest.raises(HTTPException) as exc_info:
        await service.ingest_owasp_top10_json(
            upload,
            framework_name="llm_top10",
            expected_control_family="LLM Security",
            user_id=1,
        )
    assert exc_info.value.status_code == 400
    assert ".json" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_ingest_rejects_empty_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _ = _make_service(monkeypatch)
    upload = _upload(
        "llm.json",
        {
            "framework": "llm_top10",
            "control_family": "LLM Security",
            "entries": [],
        },
    )
    with pytest.raises(HTTPException) as exc_info:
        await service.ingest_owasp_top10_json(
            upload,
            framework_name="llm_top10",
            expected_control_family="LLM Security",
            user_id=1,
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_starter_content_files_validate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: the canonical starter-content JSON files in
    `data/owasp/` ingest cleanly. Catches schema drift between the
    JSON files and the ingest method as the content evolves."""
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent
    llm_path = repo_root / "data" / "owasp" / "llm_top10_2025.json"
    agentic_path = repo_root / "data" / "owasp" / "agentic_top10_2026.json"

    service, fake_rag = _make_service(monkeypatch)

    with open(llm_path, "rb") as fp:
        llm_upload = UploadFile(
            filename="llm_top10_2025.json", file=io.BytesIO(fp.read())
        )
    result = await service.ingest_owasp_top10_json(
        llm_upload,
        framework_name="llm_top10",
        expected_control_family="LLM Security",
        user_id=1,
    )
    assert result["count"] == 10  # LLM01..LLM10

    fake_rag.delete_by_framework.reset_mock()
    fake_rag.add.reset_mock()

    with open(agentic_path, "rb") as fp:
        agentic_upload = UploadFile(
            filename="agentic_top10_2026.json", file=io.BytesIO(fp.read())
        )
    result = await service.ingest_owasp_top10_json(
        agentic_upload,
        framework_name="agentic_top10",
        expected_control_family="Agentic Security",
        user_id=1,
    )
    assert result["count"] == 10  # AGENT01..AGENT10

"""Upload filename guards are segment-aware, not substring tests.

The regression these hold: a browser upload of a legitimate Next.js catch-all
route file (`[...slug].tsx`) was refused with "Invalid filename", because the
guard tested for `".."` anywhere in the name. Traversal is a `..` *path
segment*; dotted filenames are ordinary code.

The `file_path` half is pure Pydantic and runs anywhere. The upload half needs
the backend runtime (config, crypto, SQLAlchemy), so it is skipped in a bare
environment and exercised by the Docker test run.
"""

from __future__ import annotations

import asyncio

import pytest

from app.core.schemas import VulnerabilityFinding

SOURCE = "export default function Page() { return null; }\n"


def _submission():
    return pytest.importorskip(
        "app.core.services.scan.submission",
        reason="needs the backend runtime dependencies; run the suite in Docker",
    )


class _StubRepo:
    """Only what `ScanSubmissionService.__init__` touches."""

    db = object()


def _upload(starlette, name: str, body: str = SOURCE):
    import io

    return starlette.UploadFile(file=io.BytesIO(body.encode()), filename=name)


def _service(submission_module, monkeypatch):
    captured: dict = {}

    async def _capture(*, files_data, **kwargs):
        captured["files_data"] = files_data
        captured["kwargs"] = kwargs
        return "scan-stub"

    service = submission_module.ScanSubmissionService(_StubRepo())
    monkeypatch.setattr(service, "_process_and_launch_scan", _capture)
    return service, captured


def test_dotted_route_filenames_are_accepted(monkeypatch) -> None:
    submission = _submission()
    starlette = pytest.importorskip("starlette.datastructures")
    service, captured = _service(submission, monkeypatch)

    asyncio.run(
        service.create_scan_from_uploads(
            files=[
                _upload(starlette, "[...slug].tsx"),
                _upload(starlette, "[[...path]].tsx"),
                _upload(starlette, "v1..2.py", "x = 1\n"),
            ],
            project_name="dotted",
        )
    )

    assert [f["path"] for f in captured["files_data"]] == [
        "[...slug].tsx",
        "[[...path]].tsx",
        "v1..2.py",
    ]


def test_traversal_upload_filenames_are_refused_and_named(monkeypatch) -> None:
    submission = _submission()
    starlette = pytest.importorskip("starlette.datastructures")
    service, _ = _service(submission, monkeypatch)

    with pytest.raises(submission.HTTPException) as excinfo:
        asyncio.run(
            service.create_scan_from_uploads(
                files=[_upload(starlette, "../../etc/passwd")],
                project_name="traversal",
            )
        )

    assert excinfo.value.status_code == 400
    # The message names the entry and the reason, so an operator knows which of
    # their picked files was refused and why.
    assert "../../etc/passwd" in excinfo.value.detail
    assert "path traversal segment" in excinfo.value.detail


def test_windows_separators_are_normalised_not_rejected(monkeypatch) -> None:
    submission = _submission()
    starlette = pytest.importorskip("starlette.datastructures")
    service, captured = _service(submission, monkeypatch)

    asyncio.run(
        service.create_scan_from_uploads(
            files=[_upload(starlette, "src\\app\\page.tsx")],
            project_name="windows",
        )
    )

    assert captured["files_data"][0]["path"] == "src/app/page.tsx"


def test_finding_file_path_allows_dotted_route_names() -> None:
    """A finding *in* a catch-all route file is real: `file_path` may hold dots."""
    for path in ("src/app/[...slug]/page.tsx", "src/app/[[...path]].tsx"):
        assert VulnerabilityFinding.validate_file_path(path) == path


def test_finding_file_path_still_rejects_traversal() -> None:
    with pytest.raises(ValueError):
        VulnerabilityFinding.validate_file_path("../../etc/passwd")
    with pytest.raises(ValueError):
        VulnerabilityFinding.validate_file_path("src/../../etc/passwd")

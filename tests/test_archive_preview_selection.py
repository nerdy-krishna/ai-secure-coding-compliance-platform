"""Archive ingest: one normal path form for preview, extraction, and selection.

Two properties these tests hold:

* a Windows-built ZIP (``\\`` separators) yields the same ``/``-separated path
  in the preview and in the extracted file set — otherwise the operator's
  selection can never match what the worker read, and a ``..\\..\\x`` traversal
  would be invisible to a ``/``-only check;
* the preview marks a row ``selectable=False`` *with a reason* instead of
  dropping it, so the tree can grey it out rather than the whole submission
  dying at ``selected_files`` validation.
"""

from __future__ import annotations

import io
import zipfile

from starlette.datastructures import UploadFile

from app.shared.lib.archive import extract_archive_to_files, list_archive_files

APP_TSX = "export const App = () => null;\n"


def _zip(entries: dict[str, str]) -> UploadFile:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buffer.seek(0)
    return UploadFile(file=buffer, filename="frontend.zip")


def test_windows_separators_are_normalised_in_the_preview() -> None:
    upload = _zip(
        {
            "secure-code-ui-main\\src\\App.tsx": APP_TSX,
            "secure-code-ui-main\\src\\app\\[...slug]\\page.tsx": APP_TSX,
            "secure-code-ui-main/README.md": "# hi\n",
        }
    )

    entries = {entry["path"]: entry for entry in list_archive_files(upload)}

    assert set(entries) == {
        "secure-code-ui-main/src/App.tsx",
        "secure-code-ui-main/src/app/[...slug]/page.tsx",
        "secure-code-ui-main/README.md",
    }
    # Dotted route filenames are ordinary code and stay selectable.
    assert all(entry["selectable"] for entry in entries.values())
    assert all(entry["reason"] is None for entry in entries.values())


def test_traversal_entries_are_listed_but_not_selectable() -> None:
    upload = _zip(
        {
            "src/app.tsx": APP_TSX,
            "..\\..\\etc\\passwd": "root:x:0:0\n",
            "../sibling/leak.ts": APP_TSX,
        }
    )

    entries = {entry["path"]: entry for entry in list_archive_files(upload)}

    assert entries["src/app.tsx"]["selectable"] is True
    blocked = {
        path: entry for path, entry in entries.items() if not entry["selectable"]
    }
    assert set(blocked) == {"../../etc/passwd", "../sibling/leak.ts"}
    assert all(
        entry["reason"] == "path traversal segment" for entry in blocked.values()
    )


def test_extraction_uses_the_same_normalised_paths() -> None:
    upload = _zip(
        {
            "secure-code-ui-main\\src\\App.tsx": APP_TSX,
            "secure-code-ui-main\\src\\index.ts": "export {};\n",
            "..\\..\\evil.ts": APP_TSX,
        }
    )

    extracted = {item["path"]: item for item in extract_archive_to_files(upload)}

    assert set(extracted) == {
        "secure-code-ui-main/src/App.tsx",
        "secure-code-ui-main/src/index.ts",
    }
    assert extracted["secure-code-ui-main/src/App.tsx"]["content"] == APP_TSX
    assert extracted["secure-code-ui-main/src/App.tsx"]["language"] == "typescript"

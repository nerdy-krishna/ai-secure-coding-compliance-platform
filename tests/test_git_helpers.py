from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.shared.lib import git as gitlib


def test_github_preview_uses_tree_api_without_total_repo_size_limit(monkeypatch):
    """Large repos should still preview selectable source files.

    The old preview cloned the repo and refused if *all* blobs exceeded
    MAX_TOTAL_BYTES, even when the processable source files were tiny.
    """

    def fake_api_json(url: str, headers=None):
        if url.endswith("/repos/owner/repo"):
            return {"default_branch": "main"}
        if url.endswith("/git/trees/main?recursive=1"):
            return {
                "truncated": False,
                "tree": [
                    {"type": "blob", "path": "src/app.py", "size": 123},
                    {
                        "type": "blob",
                        "path": "data/huge.bin",
                        "size": gitlib.MAX_TOTAL_BYTES + 1,
                    },
                    {
                        "type": "blob",
                        "path": "assets/picture.jpg",
                        "size": 6 * 1024 * 1024,
                    },
                ],
            }
        raise AssertionError(url)

    def fail_clone(_repo_url):
        raise AssertionError("preview should not clone GitHub repositories")

    monkeypatch.setattr(gitlib, "_github_api_json", fake_api_json)
    monkeypatch.setattr(gitlib, "clone_repo_and_get_files", fail_clone)

    assert gitlib.list_repo_files("https://github.com/owner/repo") == [
        {"path": "assets/picture.jpg", "language": "unknown", "supported": False},
        {"path": "data/huge.bin", "language": "unknown", "supported": False},
        {"path": "src/app.py", "language": "python", "supported": True},
    ]


def test_fetch_github_selected_files_downloads_only_selected_paths(monkeypatch):
    raw_body = "print('hello')\n"

    def fake_api_json(url: str, headers=None):
        if url.endswith("/repos/owner/repo"):
            return {"default_branch": "main"}
        if url.endswith("/git/trees/main?recursive=1"):
            return {
                "truncated": False,
                "tree": [
                    {"type": "blob", "path": "src/app.py", "size": len(raw_body)},
                    {"type": "blob", "path": "src/skip.py", "size": 20},
                ],
            }
        raise AssertionError(url)

    requested_urls: list[str] = []

    def fake_urlopen(req, timeout=30):
        requested_urls.append(req.full_url)

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size=-1):
                data = raw_body.encode()
                return data if size < 0 else data[:size]

        return Response()

    monkeypatch.setattr(gitlib, "_github_api_json", fake_api_json)
    monkeypatch.setattr(gitlib.urllib.request, "urlopen", fake_urlopen)

    files = gitlib.fetch_github_selected_files(
        "https://github.com/owner/repo", ["src/app.py"]
    )

    assert files == [{"path": "src/app.py", "content": raw_body, "language": "python"}]
    assert requested_urls == [
        "https://raw.githubusercontent.com/owner/repo/main/src/app.py"
    ]


def test_fetch_github_selected_files_rejects_unknown_selection(monkeypatch):
    def fake_api_json(url: str, headers=None):
        if url.endswith("/repos/owner/repo"):
            return {"default_branch": "main"}
        if url.endswith("/git/trees/main?recursive=1"):
            return {"truncated": False, "tree": []}
        raise AssertionError(url)

    monkeypatch.setattr(gitlib, "_github_api_json", fake_api_json)

    with pytest.raises(HTTPException) as exc:
        gitlib.fetch_github_selected_files("https://github.com/owner/repo", ["nope.py"])

    assert exc.value.status_code == 400
    assert "Unknown selected files" in exc.value.detail

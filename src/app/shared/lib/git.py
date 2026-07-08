"""src/app/shared/lib/git.py

Bounded, validated repository cloning helper.

Security properties enforced by ``clone_repo_and_get_files``:

* Accepted URL schemes: ``https://`` only.
* Accepted hosts: an allow-list of public Git providers
  (``github.com``, ``gitlab.com``, ``bitbucket.org``). Localhost,
  RFC1918, link-local, and loopback resolutions are rejected (SSRF
  defence).
* Rejects ``file://``, ``ssh://``, ``git://``, ``ext::``, and other
  transport-helper smuggling patterns.
* Rejects URLs containing control characters, embedded credentials
  (``@``-userinfo), shell metacharacters, or characters that can
  trigger git option-injection (``-`` prefix, ``--upload-pack=`` etc.).
* Caps URL length at 2048 characters.
* Shallow clone (``depth=1``, ``--single-branch``, ``--no-tags``).
* ``GIT_TERMINAL_PROMPT=0`` and ``GIT_HTTP_LOW_SPEED_LIMIT`` /
  ``GIT_HTTP_LOW_SPEED_TIME`` so a stalled remote does not pin the
  worker. ``kill_after_timeout=120`` aborts a clone exceeding 120s of
  wall time. (Bounded clone protects V15.1.3 availability.)
* Refuses repositories whose total on-disk size exceeds
  ``MAX_TOTAL_BYTES`` (500 MB) or that contain more than
  ``MAX_FILES`` (10 000) files. Skips individual files larger than
  ``MAX_FILE_BYTES`` (5 MB).
* ``os.walk`` runs with ``followlinks=False`` and per-file realpath
  containment checks so a malicious symlink cannot escape the temp
  clone.
* Skips files whose extension is not recognised by
  ``get_language_from_filename`` and skips files whose first bytes
  match common executable magic (``MZ``, ``\\x7fELF``, Mach-O).
* HTTPException details returned to the API caller never include git
  stderr or other server-side internals; full error text is captured
  in the server log only.
* All log lines redact userinfo from ``repo_url`` (token-leak
  defence) and use ``%s`` lazy formatting (log-injection defence).
"""

import json
import logging
import os
import re
import shutil
import socket
import tempfile
import urllib.request
from ipaddress import ip_address
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urlparse, urlunparse

from fastapi import HTTPException

# Import GitPython. If 'git' executable is not found, GitPython's import
# itself will raise an ImportError with a descriptive message.
import git

# Import the moved function
from app.shared.lib.files import get_language_from_filename

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------
ALLOWED_SCHEMES = {"https"}
ALLOWED_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
MAX_URL_LEN = 2048
URL_PRINTABLE_RE = re.compile(r"^[A-Za-z0-9._:/?=&#%+\-]+$")

# Resource caps
MAX_FILES = 10_000
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB per file
MAX_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB total tree
CLONE_TIMEOUT_SECONDS = 120
GITHUB_API_TIMEOUT_SECONDS = 30

# Executable magic bytes; binaries that match are skipped.
_EXEC_MAGIC = (
    b"MZ",  # PE / DOS
    b"\x7fELF",  # ELF
    b"\xfe\xed\xfa\xce",  # Mach-O 32 BE
    b"\xce\xfa\xed\xfe",  # Mach-O 32 LE
    b"\xfe\xed\xfa\xcf",  # Mach-O 64 BE
    b"\xcf\xfa\xed\xfe",  # Mach-O 64 LE
    b"\xca\xfe\xba\xbe",  # Mach-O fat
)


def _redact_url(url: str) -> str:
    """Strip userinfo (and any embedded credentials) from a URL for logging."""
    try:
        p = urlparse(url)
        netloc = p.hostname or ""
        if p.port:
            netloc += f":{p.port}"
        return urlunparse(p._replace(netloc=netloc, scheme=p.scheme))
    except Exception:
        return "<unparseable>"


def _validate_repo_url(repo_url: str) -> None:
    """Validate ``repo_url`` against scheme/host/length/character allow-lists.

    Raises ``HTTPException(400, ...)`` on any rejection. The caller-facing
    detail is a sanitised, fixed string; the underlying reason is logged.
    """
    if not isinstance(repo_url, str) or not repo_url:
        raise HTTPException(status_code=400, detail="repo_url is not a valid string")
    if len(repo_url) > MAX_URL_LEN:
        raise HTTPException(status_code=400, detail="repo_url exceeds maximum length")

    # Reject control characters, NUL bytes, and option-injection prefixes.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in repo_url):
        raise HTTPException(
            status_code=400, detail="repo_url contains control characters"
        )
    if "\x00" in repo_url or "%00" in repo_url:
        raise HTTPException(status_code=400, detail="repo_url contains NUL byte")
    if ".." in repo_url:
        raise HTTPException(status_code=400, detail="repo_url contains path traversal")
    if repo_url.startswith("-"):
        raise HTTPException(
            status_code=400, detail="repo_url has option-injection prefix"
        )
    if "::" in repo_url:
        raise HTTPException(
            status_code=400, detail="repo_url contains forbidden characters"
        )
    if not URL_PRINTABLE_RE.fullmatch(repo_url):
        raise HTTPException(
            status_code=400, detail="repo_url contains disallowed characters"
        )

    parsed = urlparse(repo_url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(
            status_code=400,
            detail="Only https:// repository URLs are supported.",
        )
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="repo_url is missing a host")
    # Embedded credentials (username:password@host) are rejected.
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise HTTPException(
            status_code=400, detail="repo_url must not contain embedded credentials"
        )

    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="repo_url is missing a host")
    if host in {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    }:  # nosec B104 — SSRF denylist (rejecting bind-all literals in repo URLs), not a service binding
        raise HTTPException(
            status_code=400, detail="Repository URL must point to an external host."
        )
    if host not in ALLOWED_HOSTS:
        raise HTTPException(
            status_code=400, detail="Repository host is not on the allow-list."
        )

    # SSRF defence: resolve the host and reject private / loopback / link-local.
    try:
        addrinfo = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="host not permitted")
    for entry in addrinfo:
        try:
            addr = ip_address(entry[4][0])
        except (ValueError, IndexError):
            continue
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            raise HTTPException(status_code=400, detail="host not permitted")


def _looks_like_executable(file_path: str) -> bool:
    """Return True when the first bytes of ``file_path`` match a known binary magic."""
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(1024)
    except OSError:
        return True  # if we cannot read it, treat as suspicious and skip
    if not header:
        return False
    for magic in _EXEC_MAGIC:
        if header.startswith(magic):
            return True
    # Heuristic: dense NULs in the first KB indicate non-text payload.
    if header.count(b"\x00") > len(header) * 0.2:
        return True
    return False


def _github_auth_headers() -> Dict[str, str]:
    """Return optional GitHub API auth headers from the process environment."""

    token = os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "sccap-git-ingest",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_api_json(
    url: str, headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers=headers or _github_auth_headers())
    try:
        with urllib.request.urlopen(  # nosec B310 - URL is constructed after strict GitHub host validation.
            request, timeout=GITHUB_API_TIMEOUT_SECONDS
        ) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("github.api_failed url=%s error=%s", url, exc)
        raise HTTPException(
            status_code=400, detail="Failed to read GitHub repository metadata."
        )


def _parse_github_repo(repo_url: str) -> Optional[Tuple[str, str]]:
    """Return (owner, repo) for a GitHub HTTPS repo URL, else None."""

    parsed = urlparse(repo_url)
    if (parsed.hostname or "").lower() != "github.com":
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner = parts[0]
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    return owner, repo


def _github_default_branch(owner: str, repo: str) -> str:
    repo_meta = _github_api_json(f"https://api.github.com/repos/{owner}/{repo}")
    branch = repo_meta.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise HTTPException(
            status_code=400, detail="GitHub repository default branch is unavailable."
        )
    return branch


def _github_tree_entries(owner: str, repo: str) -> List[Dict[str, Any]]:
    branch = _github_default_branch(owner, repo)
    encoded_branch = quote(branch, safe="")
    tree = _github_api_json(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{encoded_branch}?recursive=1"
    )
    if tree.get("truncated"):
        raise HTTPException(
            status_code=413,
            detail="Repository file tree is too large to preview via GitHub API.",
        )
    entries = tree.get("tree")
    if not isinstance(entries, list):
        raise HTTPException(
            status_code=400, detail="GitHub repository file tree is unavailable."
        )
    return entries


def _is_processable_tree_entry(entry: Dict[str, Any]) -> bool:
    if entry.get("type") != "blob":
        return False
    path = entry.get("path")
    if not isinstance(path, str) or not path:
        return False
    if (
        path.startswith("/")
        or ".." in path.split("/")
        or "\x00" in path
        or "\\" in path
    ):
        return False
    if get_language_from_filename(path) is None:
        return False
    size = entry.get("size")
    if not isinstance(size, int) or size < 0 or size > MAX_FILE_BYTES:
        return False
    return True


def list_repo_files(repo_url: str) -> List[Dict[str, Any]]:
    """Return ALL source file paths with support status for preview."""

    _validate_repo_url(repo_url)
    github_repo = _parse_github_repo(repo_url)
    if github_repo is None:
        # Non-GitHub: clone and list all files
        entries = []
        for f in clone_repo_and_get_files(repo_url):
            language = get_language_from_filename(f["path"]) or "unknown"
            entries.append(
                {
                    "path": f["path"],
                    "language": language,
                    "supported": language != "unknown",
                }
            )
        return entries

    owner, repo = github_repo
    entries = []
    for entry in _github_tree_entries(owner, repo):
        if entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            continue
        if (
            path.startswith("/")
            or ".." in path.split("/")
            or "\x00" in path
            or "\\" in path
        ):
            continue
        language = get_language_from_filename(path) or "unknown"
        size = entry.get("size", 0)
        entries.append(
            {
                "path": path,
                "language": language,
                "supported": language != "unknown"
                and isinstance(size, int)
                and 0 <= size <= MAX_FILE_BYTES,
            }
        )

    if len(entries) > MAX_FILES:
        raise HTTPException(
            status_code=413, detail="Repository exceeds maximum file count"
        )
    return sorted(entries, key=lambda e: e["path"])


def fetch_github_selected_files(
    repo_url: str, selected_files: Iterable[str]
) -> List[Dict[str, str]]:
    """Fetch only selected processable files from GitHub raw URLs."""

    _validate_repo_url(repo_url)
    github_repo = _parse_github_repo(repo_url)
    if github_repo is None:
        raise HTTPException(
            status_code=400,
            detail="Selected-file Git fetch is only supported for GitHub URLs.",
        )

    selected = list(dict.fromkeys(selected_files))
    if not selected:
        raise HTTPException(status_code=400, detail="No selected files were provided.")
    if len(selected) > MAX_FILES:
        raise HTTPException(
            status_code=413, detail="Repository exceeds maximum file count"
        )

    owner, repo = github_repo
    branch = _github_default_branch(owner, repo)
    allowed_paths = {
        entry["path"]: entry
        for entry in _github_tree_entries(owner, repo)
        if _is_processable_tree_entry(entry)
    }
    unknown = set(selected) - set(allowed_paths)
    if unknown:
        sample = sorted(unknown)[:5]
        raise HTTPException(
            status_code=400,
            detail=f"Unknown selected files (showing up to 5): {sample}",
        )

    files_data: List[Dict[str, str]] = []
    total_bytes = 0
    headers = _github_auth_headers()
    for path in selected:
        size = int(allowed_paths[path].get("size") or 0)
        if total_bytes + size > MAX_TOTAL_BYTES:
            raise HTTPException(
                status_code=413, detail="Repository exceeds maximum total size"
            )
        raw_url = (
            "https://raw.githubusercontent.com/"
            f"{owner}/{repo}/{quote(branch, safe='')}/{quote(path, safe='/')}"
        )
        try:
            request = urllib.request.Request(raw_url, headers=headers)
            with urllib.request.urlopen(  # nosec B310 - URL is constructed from validated GitHub owner/repo/path.
                request, timeout=GITHUB_API_TIMEOUT_SECONDS
            ) as response:
                raw = response.read(MAX_FILE_BYTES + 1)
        except Exception as exc:
            logger.warning(
                "github.raw_failed repo=%s path=%s error=%s",
                _redact_url(repo_url),
                path,
                exc,
            )
            raise HTTPException(
                status_code=400, detail="Failed to read selected GitHub file."
            )
        if len(raw) > MAX_FILE_BYTES:
            raise HTTPException(
                status_code=413, detail="Selected file exceeds maximum size"
            )
        content = raw.decode("utf-8", errors="ignore").replace("\x00", "")
        total_bytes += len(content.encode())
        files_data.append(
            {
                "path": path,
                "content": content,
                "language": get_language_from_filename(path) or "unknown",
            }
        )
    return files_data


def clone_repo_and_get_files(repo_url: str) -> List[Dict[str, str]]:
    """Clone a Git repository to a temporary directory and extract files.

    Refuses repos with more than ``MAX_FILES`` files or larger than
    ``MAX_TOTAL_BYTES``. Skips files larger than ``MAX_FILE_BYTES`` and
    files whose extension is not recognised or whose magic bytes look
    like an executable. Only ``https://`` URLs on an allow-listed host
    are accepted; embedded credentials and SSRF-style targets are
    rejected.
    """
    _validate_repo_url(repo_url)

    files_data: List[Dict[str, str]] = []
    total_bytes = 0
    temp_dir = tempfile.mkdtemp()
    try:
        logger.info("Cloning repository %s to %s", _redact_url(repo_url), temp_dir)
        clone_env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_HTTP_LOW_SPEED_LIMIT": "1000",
            "GIT_HTTP_LOW_SPEED_TIME": "30",
            "GIT_HTTP_MAX_REQUESTS": "1",
        }
        git.Repo.clone_from(
            repo_url,
            temp_dir,
            depth=1,
            multi_options=["--single-branch", "--no-tags"],
            env=clone_env,
            kill_after_timeout=CLONE_TIMEOUT_SECONDS,
        )

        # Pre-flight: refuse oversize trees before reading any file.
        tree_size = 0
        for r, _dirs, fs in os.walk(temp_dir, followlinks=False):
            if ".git" in r.split(os.sep):
                continue
            for f in fs:
                try:
                    tree_size += os.path.getsize(os.path.join(r, f))
                except OSError:
                    continue
                if tree_size > MAX_TOTAL_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="Repository exceeds maximum total size",
                    )

        real_temp_dir = os.path.realpath(temp_dir) + os.sep
        for root, _, filenames in os.walk(temp_dir, followlinks=False):
            if ".git" in root.split(os.sep):  # Skip .git directory
                continue
            for filename in filenames:
                file_path = os.path.join(root, filename)

                # Symlink containment: refuse links and refuse paths whose
                # realpath escapes the temp clone.
                if os.path.islink(file_path):
                    continue
                real_path = os.path.realpath(file_path)
                if not real_path.startswith(real_temp_dir):
                    continue

                # Extension allow-list via the language detector.
                language = get_language_from_filename(filename)
                if language is None:
                    continue

                # File-count cap.
                if len(files_data) >= MAX_FILES:
                    logger.warning(
                        "clone_repo_and_get_files: hit MAX_FILES=%s for %s",
                        MAX_FILES,
                        _redact_url(repo_url),
                    )
                    raise HTTPException(
                        status_code=413,
                        detail="Repository exceeds maximum file count",
                    )

                # Per-file size cap.
                try:
                    fsize = os.path.getsize(file_path)
                except OSError:
                    continue
                if fsize > MAX_FILE_BYTES:
                    logger.info(
                        "Skipping %s: %s bytes > MAX_FILE_BYTES",
                        file_path,
                        fsize,
                    )
                    continue
                if total_bytes + fsize > MAX_TOTAL_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="Repository exceeds maximum total size",
                    )

                # Magic-byte check: skip executables and binary blobs.
                if _looks_like_executable(file_path):
                    continue

                relative_path = os.path.relpath(file_path, temp_dir)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    # Remove null bytes, as they are invalid in PostgreSQL UTF-8 strings
                    content = content.replace("\x00", "")
                    total_bytes += fsize
                    files_data.append(
                        {
                            "path": relative_path,
                            "content": content,
                            "language": language
                            or "unknown",  # Default to unknown if not recognized
                        }
                    )
                except Exception as e:
                    logger.warning(
                        "Could not read or process file %s: %s", file_path, e
                    )
        logger.info(
            "Successfully extracted %d files from %s",
            len(files_data),
            _redact_url(repo_url),
        )
    except HTTPException:
        # Already-sanitised; re-raise unchanged.
        raise
    except git.GitCommandError:
        logger.error("git.clone_failed repo=%s", _redact_url(repo_url), exc_info=True)
        raise HTTPException(status_code=400, detail="Failed to clone repository.")
    except Exception:
        logger.error(
            "git.process_failed repo=%s",
            _redact_url(repo_url),
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Error processing repository.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)  # Clean up the temporary directory
    return files_data

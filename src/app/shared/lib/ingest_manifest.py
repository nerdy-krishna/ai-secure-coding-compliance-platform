"""The one place a submission's files are accepted, classified and counted.

Every ingestion path — browser upload, pasted code, archive, git clone — ends up
here, so they cannot drift apart again about what is too large, what is binary,
what is empty, or what counts as source.

The manifest answers three questions with evidence:

* **Was the file taken?** Each file is either an entry or a skipped record with a
  reason code (``invalid_path``, ``duplicate_path``, ``empty_input``,
  ``binary_input``, ``input_size_limit``, ``total_size_limit``, ``file_limit``,
  ``unsupported_file_type``, ``unsupported_language``). Nothing disappears quietly.
* **What is it?** Role and language come from the shared classifier, so a
  hand-written module inside ``build/`` is first-party and a generated bundle
  outside it is not.
* **Will anything read it?** Capability (``scanners_for``) crossed with role
  (``split_scanners``), honouring the operator's deep-vendor-scan choice.

The same manifest powers the submission guard — a submission whose every file
would be skipped is refused up front, with the reason breakdown, instead of
producing an empty scan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.shared.lib import ingest_limits
from app.shared.lib.file_classification import classify_file, split_scanners
from app.shared.lib.language_registry import language_for, scanners_for

logger = logging.getLogger(__name__)

#: Skip reasons, longest-lived first. Kept as constants so the API, the coverage
#: manifest and the UI cannot disagree about the vocabulary.
SKIP_INVALID_PATH = "invalid_path"
SKIP_DUPLICATE_PATH = "duplicate_path"
SKIP_EMPTY = "empty_input"
SKIP_BINARY = "binary_input"
SKIP_FILE_SIZE = "input_size_limit"
SKIP_TOTAL_SIZE = "total_size_limit"
SKIP_FILE_LIMIT = "file_limit"
SKIP_UNSUPPORTED_TYPE = "unsupported_file_type"
SKIP_UNSUPPORTED_LANGUAGE = "unsupported_language"


@dataclass(frozen=True)
class FileEntry:
    """An accepted file, with everything downstream needs to plan it."""

    path: str
    size: int
    language: Optional[str]
    role: str
    scanners: Tuple[str, ...]
    allowed_scanners: Tuple[str, ...]
    denied_scanners: Tuple[str, ...]

    @property
    def scannable(self) -> bool:
        return bool(self.allowed_scanners)


@dataclass(frozen=True)
class SkipRecord:
    path: str
    reason_code: str
    reason: str
    size: int = 0


@dataclass
class IngestManifest:
    """The result of ingesting one submission."""

    source: str
    entries: Dict[str, FileEntry] = field(default_factory=dict)
    contents: Dict[str, str] = field(default_factory=dict)
    skipped: List[SkipRecord] = field(default_factory=list)
    received: int = 0
    deep_vendor_scan: bool = False
    limits: Dict[str, int] = field(default_factory=dict)

    # -- simple views -------------------------------------------------------
    @property
    def files_total(self) -> int:
        return self.received

    @property
    def scannable_paths(self) -> List[str]:
        return [entry.path for entry in self.entries.values() if entry.scannable]

    @property
    def scannable(self) -> int:
        return len(self.scannable_paths)

    @property
    def first_party(self) -> int:
        """Files whose content is the submitter's own source."""
        return sum(1 for entry in self.entries.values() if entry.role == "first_party_source")

    def files(self) -> Dict[str, str]:
        """Contents of the files that will actually be scanned."""
        return {path: self.contents[path] for path in self.scannable_paths}

    def files_for_persistence(self) -> List[Dict[str, str]]:
        """``{path, content, language}`` rows, in submission order."""
        return [
            {
                "path": entry.path,
                "content": self.contents[entry.path],
                "language": entry.language or "text",
            }
            for entry in self.entries.values()
        ]

    def reason_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for record in self.skipped:
            counts[record.reason_code] = counts.get(record.reason_code, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: -item[1]))

    def role_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for entry in self.entries.values():
            counts[entry.role] = counts.get(entry.role, 0) + 1
        for record in self.skipped:
            if record.reason_code in {SKIP_EMPTY, SKIP_BINARY}:
                role = "empty" if record.reason_code == SKIP_EMPTY else "binary"
                counts[role] = counts.get(role, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: -item[1]))

    def summary(self) -> Dict[str, Any]:
        reasons = self.reason_counts()
        top = ", ".join(
            f"{reason.replace('_', ' ')} {count}" for reason, count in list(reasons.items())[:4]
        )
        message = (
            f"Received {self.files_total} file(s) from {self.source}: "
            f"{self.scannable} will be scanned"
        )
        if self.skipped:
            message += f", {len(self.skipped)} skipped" + (f" ({top})" if top else "")
        return {
            "source": self.source,
            "files_total": self.files_total,
            "files_accepted": len(self.entries),
            "files_scannable": self.scannable,
            "files_first_party": self.first_party,
            "files_skipped": len(self.skipped),
            "bytes_accepted": sum(entry.size for entry in self.entries.values()),
            "roles": self.role_counts(),
            "excluded_by_reason": reasons,
            "deep_vendor_scan": self.deep_vendor_scan,
            "limits": self.limits,
            "message": message + ".",
        }

    def vendor_only_detail(self) -> str:
        """Explanation for a submission that is entirely vendored or generated."""
        roles = self.role_counts()
        breakdown = ", ".join(
            f"{count} {role.replace('_', ' ')}" for role, count in list(roles.items())[:4]
        )
        return (
            f"None of the {self.files_total} submitted file(s) is your own source code "
            f"({breakdown}). These are dependencies or generated output — submitting "
            "them audits third-party code you cannot fix. Submit your project sources, "
            "or enable 'Scan vendor and generated files' to analyse them anyway."
        )

    def rejection_detail(self) -> str:
        """Human-readable explanation for a submission nothing can scan."""
        reasons = self.reason_counts()
        parts = [f"{count} {reason.replace('_', ' ')}" for reason, count in reasons.items()]
        detail = (
            f"None of the {self.files_total} submitted file(s) can be scanned: "
            + (", ".join(parts) if parts else "every file was excluded")
            + "."
        )
        if any(code in reasons for code in (SKIP_BINARY, SKIP_EMPTY)):
            detail += " Submit text source files."
        if reasons.get(SKIP_UNSUPPORTED_LANGUAGE) or reasons.get(SKIP_UNSUPPORTED_TYPE):
            detail += " Submit source code in a supported language."
        if (
            reasons.get("low_value_role")
            or any("vendor" in str(record.reason) for record in self.skipped)
        ):
            detail += (
                " If these are vendored dependencies, enable 'scan vendor and "
                "generated files' to analyse them anyway."
            )
        return detail


def _normalise_path(raw: str) -> Optional[str]:
    """Return a safe relative POSIX path, or None when it must be refused."""
    path = (raw or "").strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if not path or path.startswith("/") or "\x00" in path:
        return None
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def build_manifest(
    items: Iterable[Any],
    *,
    source: str,
    deep_vendor_scan: bool = False,
    max_files: Optional[int] = None,
    max_total_bytes: Optional[int] = None,
    max_file_bytes: Optional[int] = None,
) -> IngestManifest:
    """Ingest *items* into one manifest.

    ``items`` accepts ``(path, content)`` pairs or dicts with ``path`` and
    ``content`` keys — the shape every reader in the codebase already produces.
    """
    file_cap = ingest_limits.MAX_FILES if max_files is None else max_files
    total_cap = ingest_limits.MAX_TOTAL_BYTES if max_total_bytes is None else max_total_bytes
    file_byte_cap = ingest_limits.MAX_FILE_BYTES if max_file_bytes is None else max_file_bytes

    manifest = IngestManifest(
        source=source,
        deep_vendor_scan=deep_vendor_scan,
        limits={
            "max_files": file_cap,
            "max_total_bytes": total_cap,
            "max_file_bytes": file_byte_cap,
        },
    )
    total_bytes = 0
    seen: set[str] = set()
    submitted: set[str] = set()

    for item in items:
        path_raw, content = _unpack(item)
        manifest.received += 1

        path = _normalise_path(path_raw)
        if path is None:
            manifest.skipped.append(
                SkipRecord(str(path_raw)[:200], SKIP_INVALID_PATH, "Path is not a safe relative path.")
            )
            continue
        if path in seen:
            manifest.skipped.append(
                SkipRecord(path, SKIP_DUPLICATE_PATH, "The same path appeared twice; the first copy was kept.")
            )
            continue

        size = len(content.encode("utf-8", "replace"))
        if size > file_byte_cap:
            manifest.skipped.append(
                SkipRecord(
                    path,
                    SKIP_FILE_SIZE,
                    f"{size} bytes exceeds the per-file limit of {file_byte_cap} bytes.",
                    size,
                )
            )
            continue
        if total_bytes + size > total_cap:
            manifest.skipped.append(
                SkipRecord(
                    path,
                    SKIP_TOTAL_SIZE,
                    f"Submission exceeded the total limit of {total_cap} bytes.",
                    size,
                )
            )
            continue
        if len(manifest.entries) >= file_cap:
            manifest.skipped.append(
                SkipRecord(path, SKIP_FILE_LIMIT, f"Submission exceeded the limit of {file_cap} files.", size)
            )
            continue

        seen.add(path)
        submitted.add(path)

        if not content.strip():
            manifest.skipped.append(
                SkipRecord(path, SKIP_EMPTY, "File has no content to analyse.", size)
            )
            continue

        profile = classify_file(path, content, submitted_paths=submitted)
        role = str(profile.get("role") or profile.get("classification") or "unknown")
        language = profile.get("language") or language_for(path)
        # The classifier also recognises comment-only files and payloads that only
        # look like text; both are unreadable in practice.
        if role == "empty":
            manifest.skipped.append(
                SkipRecord(path, SKIP_EMPTY, "File has no code to analyse.", size)
            )
            continue
        if role == "binary":
            manifest.skipped.append(
                SkipRecord(path, SKIP_BINARY, "File is binary or compiled, not source.", size)
            )
            continue
        capable = scanners_for(path)
        if not capable:
            reason = (
                SKIP_UNSUPPORTED_LANGUAGE
                if language
                else SKIP_UNSUPPORTED_TYPE
            )
            manifest.skipped.append(
                SkipRecord(
                    path,
                    reason,
                    f"No scanner can read {language or 'this file type'}.",
                    size,
                )
            )
            continue

        allowed, denied = split_scanners(capable, profile, deep_vendor_scan)
        manifest.contents[path] = content
        manifest.entries[path] = FileEntry(
            path=path,
            size=size,
            language=language,
            role=role,
            scanners=tuple(capable),
            allowed_scanners=tuple(allowed),
            denied_scanners=tuple(denied),
        )
        total_bytes += size

    # ``submitted`` grows during the loop, so the build-manifest lookup in the
    # classifier only ever sees files already accepted — a build output can still be
    # recognised when its manifest sibling arrives after it.
    logger.info("ingest manifest built: %s", manifest.summary()["message"])
    return manifest


def _unpack(item: Any) -> Tuple[str, str]:
    if isinstance(item, dict):
        content = item.get("content")
        return str(item.get("path") or ""), content if isinstance(content, str) else ""
    if isinstance(item, Sequence) and len(item) == 2:
        path, content = item
        return str(path), content if isinstance(content, str) else ""
    raise TypeError(f"Unsupported ingest item: {type(item)!r}")

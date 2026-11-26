"""Validation for the ``selected_files`` scan-submission field.

The UI joins the paths the operator ticked in the preview tree into one
comma-separated ``selected_files`` form field. Those entries came back from
``/scans/preview-archive`` or ``/scans/preview-git``, so they are ordinary
archive members or repository paths.

Validation is per entry and **segment-aware** on purpose. A substring test for
``..`` refuses legitimate filenames - Next.js catch-all routes such as
``[...slug].tsx`` or ``[[...path]].tsx`` - which are real application code
whose parameters are exactly the kind of thing worth scanning. Only a ``..``
*path segment* is traversal (V05.3.2).

Every rejection names the offending entry, because a message that says
"selected_files contains invalid characters" over a list of a thousand picked
paths gives the operator nothing to act on.
"""

from __future__ import annotations

import posixpath

MAX_SELECTED_FILES = 5000
MAX_SELECTED_FILES_CHARS = 200_000

# How much of the payload goes back to the operator: enough to identify the
# file, small enough to survive a toast notification.
_REPORTED_ENTRIES = 3
_ENTRY_REPORT_CHARS = 120

_REMEDY = (
    "Untick the affected files in the preview tree and submit again. If they "
    "came from an archive, re-create it with an archiver that writes '/' "
    "separators (e.g. `zip -rX`, macOS Finder, or `tar`), not one that writes "
    "Windows '\\' separators."
)


class SelectedFilesError(ValueError):
    """A ``selected_files`` payload that must be refused.

    Carries the HTTP status the router should use so the field's rules stay in
    one place instead of being re-derived at each call site.
    """

    def __init__(self, detail: str, status_code: int = 400) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def _clip(entry: str) -> str:
    """Render one entry for a response body without echoing unbounded input."""
    if len(entry) <= _ENTRY_REPORT_CHARS:
        return entry
    return entry[:_ENTRY_REPORT_CHARS] + "..."


def normalize_entry_name(name: str) -> str:
    """Normalise one archive member name to a ``/``-separated relative path.

    ZIP entries built on Windows can carry ``\\`` separators (PowerShell 5.1
    ``Compress-Archive``, .NET Framework ``ZipFile.CreateFromDirectory``). The
    archive itself is fine, but every layer has to agree on the name: the
    preview the operator picks from and the extraction that reads the file. It
    also matters for safety - ``..\\..\\etc\\passwd`` is a traversal that a
    ``/``-only check cannot see.

    NULs are dropped and the result is lexically normalised with
    ``posixpath.normpath`` (never ``os.path.normpath``, which would re-introduce
    backslashes on Windows). A real traversal is left intact so
    ``rejection_reason`` can still refuse it.
    """
    cleaned = name.replace("\x00", "").replace("\\", "/")
    if not cleaned:
        return ""
    return posixpath.normpath(cleaned)


def rejection_reason(entry: str) -> str | None:
    """Return why ``entry`` is unsafe, or ``None`` when it is a plain path.

    Segment-aware: ``[...slug].tsx`` and ``v1..2.py`` pass, ``../secrets.env``
    and ``src/../../etc/passwd`` do not.
    """
    if "\x00" in entry:
        return "null byte"
    if "\\" in entry:
        return "backslash path separator"
    if entry.startswith("/"):
        return "absolute path"
    if len(entry) > 1 and entry[1] == ":" and entry[0].isalpha():
        return "absolute path"
    if ".." in entry.split("/"):
        return "path traversal segment"
    return None


def _format_rejection(offenders: list[tuple[str, str]]) -> str:
    """One actionable sentence naming what was wrong and where it was."""
    count = len(offenders)
    shown = "; ".join(
        f"{_clip(entry)!r} ({reason})"
        for entry, reason in offenders[:_REPORTED_ENTRIES]
    )
    ellipsis = (
        "" if count <= _REPORTED_ENTRIES else f"; and {count - _REPORTED_ENTRIES} more"
    )
    noun = "entry" if count == 1 else "entries"
    return (
        f"selected_files contains {count} unusable {noun} "
        f"(showing up to {_REPORTED_ENTRIES}): {shown}{ellipsis}. {_REMEDY}"
    )


def split_selected_files(raw: str | None) -> list[str] | None:
    """Parse the comma-separated ``selected_files`` form field.

    Returns ``None`` when nothing was selected (meaning "scan everything"),
    otherwise the de-duplicated entries in submission order.

    Raises:
        SelectedFilesError: an entry is unsafe (400) or there are too many
            entries (413).
    """
    if not raw:
        return None

    entries = list(dict.fromkeys(p.strip() for p in raw.split(",") if p.strip()))
    if not entries:
        return None
    if len(entries) > MAX_SELECTED_FILES:
        raise SelectedFilesError(
            f"Too many entries in selected_files "
            f"(max {MAX_SELECTED_FILES}, got {len(entries)}).",
            status_code=413,
        )

    offenders = [
        (entry, reason) for entry in entries if (reason := rejection_reason(entry))
    ]
    if offenders:
        raise SelectedFilesError(_format_rejection(offenders))

    return entries

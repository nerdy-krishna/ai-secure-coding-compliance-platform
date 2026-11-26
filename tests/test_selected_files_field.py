"""``selected_files`` field validation: segment-aware, and it names the offender.

The contract these tests hold:

* a filename that merely *contains* dots passes - Next.js catch-all routes
  (``[...slug].tsx``, ``[[...path]].tsx``) are ordinary application code and
  must stay scannable;
* traversal is a ``..`` **segment**, and an absolute path, a NUL byte, or a
  Windows separator is still refused;
* every refusal names the offending entry, because "contains invalid
  characters" against a list of a thousand ticks is unactionable.
"""

from __future__ import annotations

import pytest

from app.shared.lib.selected_files import (
    MAX_SELECTED_FILES,
    SelectedFilesError,
    normalize_entry_name,
    rejection_reason,
    split_selected_files,
)


def test_nextjs_catch_all_routes_are_not_traversal() -> None:
    """The regression: dotted route filenames are valid code, not escapes."""
    entries = [
        "src/app/[...slug]/page.tsx",
        "src/app/docs/[[...path]].tsx",
        "src/..path.tsx",
        "src/v1..2/handler.py",
        "app/@modal/(.)photo/page.tsx",
    ]

    assert split_selected_files(",".join(entries)) == entries
    for entry in entries:
        assert rejection_reason(entry) is None, entry


def test_traversal_entries_are_rejected_and_named() -> None:
    with pytest.raises(SelectedFilesError) as excinfo:
        split_selected_files("src/app.tsx,../secrets.env,src/../../etc/passwd")

    error = excinfo.value
    assert error.status_code == 400
    assert "'../secrets.env' (path traversal segment)" in error.detail
    assert "'src/../../etc/passwd' (path traversal segment)" in error.detail
    # The innocent file is not blamed.
    assert "'src/app.tsx'" not in error.detail


def test_absolute_nul_and_backslash_entries_are_rejected() -> None:
    with pytest.raises(SelectedFilesError) as excinfo:
        split_selected_files(
            "/etc/passwd,src/a\x00b.ts,C:\\repo\\a.ts,src\\app.tsx,C:/repo/b.ts"
        )

    detail = excinfo.value.detail
    assert "'src/a\\x00b.ts' (null byte)" in detail
    assert "'C:\\\\repo\\\\a.ts' (backslash path separator)" in detail
    # Only the first few offenders are echoed; the rest are counted.
    assert "contains 5 unusable entries" in detail


def test_absolute_paths_are_rejected() -> None:
    with pytest.raises(SelectedFilesError) as excinfo:
        split_selected_files("/etc/passwd,C:/repo/b.ts")

    detail = excinfo.value.detail
    assert "'/etc/passwd' (absolute path)" in detail
    assert "'C:/repo/b.ts' (absolute path)" in detail


def test_rejection_names_are_capped_but_counted() -> None:
    entries = [f"../escape{i}.ts" for i in range(7)]

    with pytest.raises(SelectedFilesError) as excinfo:
        split_selected_files(",".join(entries))

    detail = excinfo.value.detail
    assert "contains 7 unusable entries" in detail
    assert "and 4 more" in detail
    assert "'../escape0.ts'" in detail
    assert "'../escape3.ts'" not in detail


def test_long_entries_are_clipped_in_the_message() -> None:
    with pytest.raises(SelectedFilesError) as excinfo:
        split_selected_files("../" + "a" * 500 + ".ts")

    detail = excinfo.value.detail
    assert "a" * 200 not in detail
    assert "'../" in detail
    assert len(detail) < 600


def test_entry_cap_is_a_413() -> None:
    payload = ",".join(f"src/f{i}.ts" for i in range(MAX_SELECTED_FILES + 1))

    with pytest.raises(SelectedFilesError) as excinfo:
        split_selected_files(payload)

    assert excinfo.value.status_code == 413
    assert f"max {MAX_SELECTED_FILES}" in excinfo.value.detail


def test_blank_and_duplicate_entries() -> None:
    assert split_selected_files(None) is None
    assert split_selected_files("") is None
    assert split_selected_files(" , ,, ") is None
    assert split_selected_files(" a.ts , a.ts ,b.ts,, ") == ["a.ts", "b.ts"]


def test_normalize_entry_name_handles_windows_zips() -> None:
    """PowerShell 5.1 / .NET Framework write '\\' into ZIP entry names."""
    assert normalize_entry_name("secure-code-ui-main\\src\\App.tsx") == (
        "secure-code-ui-main/src/App.tsx"
    )
    # Normalising is what makes the traversal visible at all.
    assert normalize_entry_name("..\\..\\etc\\passwd") == "../../etc/passwd"
    assert rejection_reason("..\\..\\etc\\passwd") is not None
    # Idempotent, and it never touches a legitimate dot-dot filename.
    assert normalize_entry_name("src/..path.tsx") == "src/..path.tsx"
    assert normalize_entry_name("./src/./app.tsx") == "src/app.tsx"
    assert normalize_entry_name("a\x00b.ts") == "ab.ts"
    assert normalize_entry_name("") == ""

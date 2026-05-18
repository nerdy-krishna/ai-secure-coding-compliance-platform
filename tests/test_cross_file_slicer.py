"""CrossFileSlicer — deterministic cross-file slice extraction (#79).

The slicer logic is exercised with a hand-built repository map and an
injected call extractor (canned call sites) — no tree-sitter at
runtime. A separate test covers the real `extract_call_sites` and is
skipped where the tree-sitter stack is unavailable.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.shared.analysis_tools.cross_file_slicer import (
    _MAX_SLICE_CHARS,
    CrossFileSlicer,
)


def _sym(name: str, type_: str, start: int, end: int) -> SimpleNamespace:
    return SimpleNamespace(
        name=name, type=type_, line_number=start, end_line_number=end
    )


def _site(name: str, line: int) -> SimpleNamespace:
    return SimpleNamespace(name=name, line_number=line)


def _finding(file_path: str, line: int, source=None) -> SimpleNamespace:
    return SimpleNamespace(file_path=file_path, line_number=line, source=source)


# A 3-file fixture codebase: api/handler.py calls auth/login.py's
# `authenticate`, which itself calls db/queries.py's `run_query`.
_CODEBASE = {
    "auth/login.py": (
        "# login module\n"
        "def authenticate(user):\n"
        "    token = get_token(user)\n"
        "    rows = run_query(token)\n"
        "    return rows\n"
    ),
    "db/queries.py": (
        "# db queries\n" "def run_query(sql):\n" "    return DB.execute(sql)\n"
    ),
    "api/handler.py": (
        "# api handler\n"
        "def handle_login(req):\n"
        "    return authenticate(req.user)\n"
    ),
    "util/lonely.py": ("# lonely util\n" "def lonely():\n" "    return 1\n"),
}

_REPO_MAP = SimpleNamespace(
    files={
        "auth/login.py": SimpleNamespace(
            symbols=[_sym("authenticate", "function_definition", 2, 5)]
        ),
        "db/queries.py": SimpleNamespace(
            symbols=[_sym("run_query", "function_definition", 2, 3)]
        ),
        "api/handler.py": SimpleNamespace(
            symbols=[_sym("handle_login", "function_definition", 2, 3)]
        ),
        "util/lonely.py": SimpleNamespace(
            symbols=[_sym("lonely", "function_definition", 2, 3)]
        ),
    }
)

_CALLS = {
    "auth/login.py": [_site("get_token", 3), _site("run_query", 4)],
    "db/queries.py": [_site("execute", 3)],
    "api/handler.py": [_site("authenticate", 3)],
    "util/lonely.py": [],
}


def _fake_extractor(file_path: str, _content: str):
    return _CALLS.get(file_path, [])


def _slicer(codebase=None, repo_map=None) -> CrossFileSlicer:
    return CrossFileSlicer(
        repo_map or _REPO_MAP,
        codebase or _CODEBASE,
        call_extractor=_fake_extractor,
    )


# --------------------------------------------------------------------------
# Caller + input-context extraction
# --------------------------------------------------------------------------


def test_extracts_cross_file_callers():
    slices = _slicer().extract_slices(_finding("auth/login.py", 4))
    callers = {(c.file_path, c.symbol_name) for c in slices.callers}
    assert ("api/handler.py", "handle_login") in callers


def test_extracts_cross_file_input_context():
    slices = _slicer().extract_slices(_finding("auth/login.py", 4))
    ctx = {(c.file_path, c.symbol_name) for c in slices.input_context}
    assert ("db/queries.py", "run_query") in ctx


def test_caller_slice_carries_the_caller_code():
    slices = _slicer().extract_slices(_finding("auth/login.py", 4))
    handler = next(c for c in slices.callers if c.symbol_name == "handle_login")
    assert "authenticate(req.user)" in handler.code


# --------------------------------------------------------------------------
# Eligibility pre-filter
# --------------------------------------------------------------------------


def test_eligible_when_finding_has_cross_file_connection():
    assert _slicer().is_eligible(_finding("auth/login.py", 4)) is True


def test_not_eligible_without_a_cross_file_connection():
    """`lonely` is never called and references nothing cross-file."""
    slicer = _slicer()
    assert slicer.is_eligible(_finding("util/lonely.py", 3)) is False
    assert slicer.extract_slices(_finding("util/lonely.py", 3)).is_empty


@pytest.mark.parametrize("source", ["gitleaks", "osv"])
def test_secret_and_cve_sources_are_never_eligible(source):
    """A leaked secret / vulnerable dependency is not a cross-file
    question — even on a finding that would otherwise connect."""
    finding = _finding("auth/login.py", 4, source=source)
    assert _slicer().is_eligible(finding) is False
    assert _slicer().extract_slices(finding).is_empty


def test_not_eligible_when_no_enclosing_function():
    """A finding on the module-level comment line has no enclosing
    function — nothing to slice."""
    assert _slicer().extract_slices(_finding("auth/login.py", 1)).is_empty


def test_unknown_file_yields_empty_slices():
    assert _slicer().extract_slices(_finding("does/not/exist.py", 3)).is_empty


# --------------------------------------------------------------------------
# Enclosing-function detection + caps
# --------------------------------------------------------------------------


def test_enclosing_symbol_picks_the_innermost_function():
    repo_map = SimpleNamespace(
        files={
            "n.py": SimpleNamespace(
                symbols=[
                    _sym("outer", "function_definition", 1, 9),
                    _sym("inner", "function_definition", 4, 6),
                ]
            ),
            "caller.py": SimpleNamespace(
                symbols=[_sym("c", "function_definition", 1, 3)]
            ),
        }
    )
    codebase = {
        "n.py": "\n".join(f"line {i}" for i in range(1, 10)) + "\n",
        "caller.py": "def c():\n    inner()\n",
    }
    calls = {"caller.py": [_site("inner", 2)], "n.py": []}
    slicer = CrossFileSlicer(
        repo_map, codebase, call_extractor=lambda p, _c: calls.get(p, [])
    )
    # A finding at line 5 sits inside both `outer` and `inner` — the
    # innermost (`inner`) is the enclosing function, so its caller is found.
    slices = slicer.extract_slices(_finding("n.py", 5))
    assert {c.symbol_name for c in slices.callers} == {"c"}


def test_slice_code_is_capped():
    big_body = "\n".join(f"    x = {i}" for i in range(4000))  # ~> _MAX_SLICE_CHARS
    repo_map = SimpleNamespace(
        files={
            "target.py": SimpleNamespace(
                symbols=[_sym("target", "function_definition", 1, 2)]
            ),
            "huge.py": SimpleNamespace(
                symbols=[_sym("huge", "function_definition", 1, 4002)]
            ),
        }
    )
    codebase = {
        "target.py": "def target():\n    pass\n",
        "huge.py": "def huge():\n" + big_body + "\n",
    }
    calls = {"huge.py": [_site("target", 2)], "target.py": []}
    slicer = CrossFileSlicer(
        repo_map, codebase, call_extractor=lambda p, _c: calls.get(p, [])
    )
    slices = slicer.extract_slices(_finding("target.py", 2))
    assert slices.callers, "expected the huge caller to be found"
    assert len(slices.callers[0].code) <= _MAX_SLICE_CHARS


# --------------------------------------------------------------------------
# Real tree-sitter call extraction
# --------------------------------------------------------------------------


def test_extract_call_sites_real_python():
    pytest.importorskip("tree_sitter_languages")
    from app.shared.analysis_tools.repository_map import extract_call_sites

    sites = extract_call_sites("t.py", "def f():\n    foo()\n    bar.baz()\n")
    names = {s.name for s in sites}
    assert "foo" in names
    assert "baz" in names


def test_extract_call_sites_unknown_language_is_empty():
    pytest.importorskip("tree_sitter_languages")
    from app.shared.analysis_tools.repository_map import extract_call_sites

    assert extract_call_sites("data.unknownext", "whatever") == []

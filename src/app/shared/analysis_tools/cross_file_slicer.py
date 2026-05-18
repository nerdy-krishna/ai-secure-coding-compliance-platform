"""CrossFileSlicer — targeted cross-file context for a finding (#79).

Cross-file finding validation re-judges a finding against the *other*
code it is connected to. Sending whole related files blows the context
window; this module extracts only the relevant slices:

- **callers** — the functions, in other files, that call the function
  the finding lives in (do they sanitise / gate the input?);
- **input context** — the cross-file symbols that function itself
  references (is the data sanitised upstream?).

It is fully deterministic — tree-sitter call sites + the repository-map
symbol index, no LLM. The eligibility pre-filter decides which findings
are worth a (paid) cross-file validation call: a finding with no
cross-file connection, or from the secret / dependency-CVE scanners, is
not eligible.

The tree-sitter call extractor is imported lazily and is injectable, so
this module imports cleanly (and is unit-testable) on hosts without the
tree-sitter stack.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Finding sources whose validity is not a cross-file-dataflow question —
# a leaked secret or a vulnerable dependency is not "compensated" by
# another file, so they are never cross-file-eligible.
_SKIP_SOURCES = frozenset({"gitleaks", "osv"})

# Caps — slices are grounding context, not the payload.
_MAX_CALLER_SLICES = 6
_MAX_INPUT_SLICES = 6
_MAX_SLICE_CHARS = 4_000

# (file_path, content) -> list of call sites (objects with .name + .line_number).
CallExtractor = Callable[[str, str], List[Any]]


@dataclass(frozen=True)
class CodeSlice:
    """One cross-file code slice — a symbol's body in another file."""

    file_path: str
    symbol_name: str
    code: str


@dataclass
class CrossFileSlices:
    """The targeted cross-file context for one finding."""

    callers: List[CodeSlice] = field(default_factory=list)
    input_context: List[CodeSlice] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.callers and not self.input_context


def _is_function_symbol(symbol: Any) -> bool:
    """True for function / method definitions (the routable units)."""
    t = (getattr(symbol, "type", "") or "").lower()
    return "function" in t or "method" in t


class CrossFileSlicer:
    """Extracts targeted cross-file slices for findings.

    Constructed once per scan with the repository map and the in-memory
    codebase; call-site extraction is cached per file so N findings cost
    one parse per file, not N. `call_extractor` is injectable for unit
    tests; production uses `repository_map.extract_call_sites`.
    """

    def __init__(
        self,
        repository_map: Any,
        codebase: Dict[str, str],
        call_extractor: Optional[CallExtractor] = None,
    ):
        self._repo_map = repository_map
        self._codebase = codebase
        self._call_extractor = call_extractor
        self._call_cache: Dict[str, List[Any]] = {}

    # -- internals ---------------------------------------------------------

    def _call_sites(self, file_path: str) -> List[Any]:
        """Call sites in a file, parsed once and cached."""
        if file_path not in self._call_cache:
            extractor = self._call_extractor
            if extractor is None:
                # Lazy import keeps the tree-sitter stack off this
                # module's import path (it is unavailable on the API image).
                from app.shared.analysis_tools.repository_map import (
                    extract_call_sites,
                )

                extractor = extract_call_sites
            source = self._codebase.get(file_path) or ""
            self._call_cache[file_path] = extractor(file_path, source)
        return self._call_cache[file_path]

    def _symbols(self, file_path: str) -> List[Any]:
        files = getattr(self._repo_map, "files", {}) or {}
        summary = files.get(file_path)
        return list(getattr(summary, "symbols", []) or []) if summary else []

    def _enclosing_symbol(self, file_path: str, line: int) -> Optional[Any]:
        """The innermost function/method symbol whose range covers `line`."""
        candidates = [
            s
            for s in self._symbols(file_path)
            if _is_function_symbol(s) and s.line_number <= line <= s.end_line_number
        ]
        if not candidates:
            return None
        # Innermost = smallest line span.
        return min(candidates, key=lambda s: s.end_line_number - s.line_number)

    def _symbol_code(self, file_path: str, symbol: Any) -> str:
        """The source of a symbol's definition, capped."""
        source = self._codebase.get(file_path) or ""
        lines = source.splitlines()
        body = "\n".join(lines[symbol.line_number - 1 : symbol.end_line_number])
        return body[:_MAX_SLICE_CHARS]

    # -- public API --------------------------------------------------------

    def extract_slices(self, finding: Any) -> CrossFileSlices:
        """Return the cross-file slices for a finding.

        An empty result (`is_empty`) means the finding has no cross-file
        connection, or is structurally not sliceable (skipped source,
        unknown file, no enclosing function).
        """
        slices = CrossFileSlices()
        if getattr(finding, "source", None) in _SKIP_SOURCES:
            return slices
        file_path = getattr(finding, "file_path", None)
        line = getattr(finding, "line_number", 0) or 0
        if not file_path or file_path not in self._codebase:
            return slices
        enclosing = self._enclosing_symbol(file_path, line)
        if enclosing is None:
            return slices

        slices.callers = self._find_callers(file_path, enclosing)
        slices.input_context = self._find_input_context(file_path, enclosing)
        return slices

    def is_eligible(self, finding: Any) -> bool:
        """True when a finding has cross-file context worth validating."""
        return not self.extract_slices(finding).is_empty

    # -- slice builders ----------------------------------------------------

    def _find_callers(self, finding_file: str, enclosing: Any) -> List[CodeSlice]:
        """Functions in *other* files that call the enclosing function."""
        callers: List[CodeSlice] = []
        seen: set[tuple[str, str, int]] = set()
        for other_path in self._codebase:
            if other_path == finding_file:
                continue
            for site in self._call_sites(other_path):
                if site.name != enclosing.name:
                    continue
                caller_sym = self._enclosing_symbol(other_path, site.line_number)
                if caller_sym is None:
                    continue
                key = (other_path, caller_sym.name, caller_sym.line_number)
                if key in seen:
                    continue
                seen.add(key)
                callers.append(
                    CodeSlice(
                        file_path=other_path,
                        symbol_name=caller_sym.name,
                        code=self._symbol_code(other_path, caller_sym),
                    )
                )
                if len(callers) >= _MAX_CALLER_SLICES:
                    return callers
        return callers

    def _find_input_context(self, finding_file: str, enclosing: Any) -> List[CodeSlice]:
        """Cross-file symbols the enclosing function itself references."""
        called_names = {
            site.name
            for site in self._call_sites(finding_file)
            if enclosing.line_number <= site.line_number <= enclosing.end_line_number
        }
        context: List[CodeSlice] = []
        seen: set[tuple[str, str]] = set()
        files = getattr(self._repo_map, "files", {}) or {}
        for name in sorted(called_names):
            if name == enclosing.name:
                continue
            for other_path, summary in files.items():
                if other_path == finding_file or other_path not in self._codebase:
                    continue
                match = next(
                    (
                        s
                        for s in (getattr(summary, "symbols", []) or [])
                        if s.name == name and _is_function_symbol(s)
                    ),
                    None,
                )
                if match is None:
                    continue
                key = (other_path, name)
                if key in seen:
                    continue
                seen.add(key)
                context.append(
                    CodeSlice(
                        file_path=other_path,
                        symbol_name=name,
                        code=self._symbol_code(other_path, match),
                    )
                )
                break  # first defining file is enough
            if len(context) >= _MAX_INPUT_SLICES:
                break
        return context

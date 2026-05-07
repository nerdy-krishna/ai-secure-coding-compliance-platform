"""SCIM 2.0 filter parser (RFC 7644 §3.4.2.2 — practical subset).

Supported grammar:

    filter      := or_expr
    or_expr     := and_expr ( "or" and_expr )*
    and_expr    := not_expr ( "and" not_expr )*
    not_expr    := "not" "(" filter ")" | atom
    atom        := "(" filter ")" | comparison
    comparison  := attr_path op value
                 | attr_path "pr"
    op          := "eq" | "ne" | "co" | "sw" | "ew"
    value       := <quoted-string> | "true" | "false"
    attr_path   := identifier ( "." identifier )*

NOT supported (returns 400 with an explanatory message):
    - gt / ge / lt / le ordering operators (not used by the IdPs we
      target for outbound provisioning)
    - complex value paths like ``emails[type eq "work"].value``
    - case-sensitive matching modifiers
    - schema-qualified attribute paths (``urn:…:User:userName``)

The parser is deliberately small + hand-rolled to keep the dependency
surface minimal. All callers map ``UnsupportedScimFilter`` to HTTP 400
with a SCIM Error response.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Literal, Optional, Sequence, Tuple, Union


class UnsupportedScimFilter(ValueError):
    """The filter uses syntax / operators we don't implement yet."""


# ----- AST -------------------------------------------------------------------


ComparisonOp = Literal["eq", "ne", "co", "sw", "ew", "pr"]
LogicalOp = Literal["and", "or", "not"]
ScimAtomicValue = Union[str, bool]


@dataclass(slots=True, frozen=True)
class ScimFilterClause:
    """Single comparison: ``attribute op value`` (or ``attribute pr``)."""

    attribute: str
    op: ComparisonOp
    # `value` is None for the `pr` (present) operator.
    value: Optional[ScimAtomicValue] = None


@dataclass(slots=True, frozen=True)
class ScimFilterGroup:
    """Logical combination of clauses or sub-groups."""

    op: LogicalOp
    # For `and` / `or`: ≥ 2 children. For `not`: exactly 1 child.
    children: Tuple["ScimFilterNode", ...]


ScimFilterNode = Union[ScimFilterClause, ScimFilterGroup]


# ----- Tokenizer -------------------------------------------------------------


_TOKEN_KINDS = {"IDENT", "STRING", "BOOL", "LPAREN", "RPAREN", "EOF"}
# Tokens we recognise as keywords (case-insensitive). Operators are all
# 2-3 letters; logical connectives are `and`/`or`/`not`.
_OPS = {"eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le"}
_REJECT_OPS = {"gt", "ge", "lt", "le"}  # parsable but explicitly rejected
_LOGICAL = {"and", "or", "not"}


@dataclass(slots=True, frozen=True)
class _Token:
    kind: str  # one of _TOKEN_KINDS or "OP" / "LOGICAL"
    value: str


def _tokenize(s: str) -> List[_Token]:
    out: List[_Token] = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            out.append(_Token("LPAREN", "("))
            i += 1
            continue
        if c == ")":
            out.append(_Token("RPAREN", ")"))
            i += 1
            continue
        if c == '"':
            # Quoted string. SCIM doesn't define escape semantics
            # explicitly; we accept "\\" and "\"" as their literal
            # characters. Any other backslash sequence raises.
            j = i + 1
            buf: List[str] = []
            while j < n and s[j] != '"':
                if s[j] == "\\":
                    if j + 1 >= n:
                        raise UnsupportedScimFilter(
                            "filter has unterminated escape sequence"
                        )
                    nxt = s[j + 1]
                    if nxt in ('"', "\\"):
                        buf.append(nxt)
                        j += 2
                        continue
                    raise UnsupportedScimFilter(
                        f"filter has unsupported escape: \\{nxt}"
                    )
                buf.append(s[j])
                j += 1
            if j >= n:
                raise UnsupportedScimFilter("filter has unterminated string")
            out.append(_Token("STRING", "".join(buf)))
            i = j + 1
            continue
        # Identifier OR keyword.
        if c.isalpha() or c == "_":
            j = i
            while j < n and (s[j].isalnum() or s[j] in "._"):
                j += 1
            word = s[i:j]
            lower = word.lower()
            if lower in _LOGICAL:
                out.append(_Token("LOGICAL", lower))
            elif lower in _OPS:
                if lower in _REJECT_OPS:
                    raise UnsupportedScimFilter(
                        f"operator {lower!r} not supported "
                        "(only eq/ne/co/sw/ew/pr are recognised)"
                    )
                out.append(_Token("OP", lower))
            elif lower == "true":
                out.append(_Token("BOOL", "true"))
            elif lower == "false":
                out.append(_Token("BOOL", "false"))
            else:
                out.append(_Token("IDENT", word))
            i = j
            continue
        raise UnsupportedScimFilter(f"unexpected character in filter: {c!r}")
    out.append(_Token("EOF", ""))
    return out


# ----- Parser (recursive descent) -------------------------------------------


class _Parser:
    def __init__(self, tokens: Sequence[_Token]):
        self.tokens = list(tokens)
        self.pos = 0

    def _peek(self, offset: int = 0) -> _Token:
        return self.tokens[self.pos + offset]

    def _eat(self, kind: str, value: Optional[str] = None) -> _Token:
        tok = self.tokens[self.pos]
        if tok.kind != kind or (value is not None and tok.value != value):
            raise UnsupportedScimFilter(
                f"expected {kind}{f'({value!r})' if value else ''}, got {tok.kind}({tok.value!r})"
            )
        self.pos += 1
        return tok

    def parse(self) -> ScimFilterNode:
        node = self._parse_or()
        if self._peek().kind != "EOF":
            raise UnsupportedScimFilter(
                f"trailing tokens after filter (got {self._peek().value!r})"
            )
        return node

    def _parse_or(self) -> ScimFilterNode:
        children: List[ScimFilterNode] = [self._parse_and()]
        while self._peek().kind == "LOGICAL" and self._peek().value == "or":
            self.pos += 1
            children.append(self._parse_and())
        if len(children) == 1:
            return children[0]
        return ScimFilterGroup(op="or", children=tuple(children))

    def _parse_and(self) -> ScimFilterNode:
        children: List[ScimFilterNode] = [self._parse_not()]
        while self._peek().kind == "LOGICAL" and self._peek().value == "and":
            self.pos += 1
            children.append(self._parse_not())
        if len(children) == 1:
            return children[0]
        return ScimFilterGroup(op="and", children=tuple(children))

    def _parse_not(self) -> ScimFilterNode:
        if self._peek().kind == "LOGICAL" and self._peek().value == "not":
            self.pos += 1
            self._eat("LPAREN")
            inner = self._parse_or()
            self._eat("RPAREN")
            return ScimFilterGroup(op="not", children=(inner,))
        return self._parse_atom()

    def _parse_atom(self) -> ScimFilterNode:
        if self._peek().kind == "LPAREN":
            self.pos += 1
            inner = self._parse_or()
            self._eat("RPAREN")
            return inner
        return self._parse_comparison()

    def _parse_comparison(self) -> ScimFilterClause:
        attr_tok = self._eat("IDENT")
        op_tok = self._eat("OP")
        op = op_tok.value  # type: ignore[assignment]
        if op == "pr":
            return ScimFilterClause(attribute=attr_tok.value, op="pr", value=None)
        # All other ops require a value.
        nxt = self._peek()
        if nxt.kind == "STRING":
            self.pos += 1
            return ScimFilterClause(attribute=attr_tok.value, op=op, value=nxt.value)
        if nxt.kind == "BOOL":
            self.pos += 1
            return ScimFilterClause(
                attribute=attr_tok.value, op=op, value=(nxt.value == "true")
            )
        raise UnsupportedScimFilter(
            f"expected string / bool after operator {op!r}, got {nxt.kind}({nxt.value!r})"
        )


def parse_filter(raw: Optional[str]) -> Optional[ScimFilterNode]:
    """Parse a SCIM filter; return None when no filter was provided.

    Raises ``UnsupportedScimFilter`` for anything we can't represent.
    """
    if raw is None or not raw.strip():
        return None
    tokens = _tokenize(raw)
    return _Parser(tokens).parse()

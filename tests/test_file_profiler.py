"""FileProfiler — per-file profiling on the utility slot (#71).

The utility LLM is mocked: the FileProfiler takes an injected client,
so these tests exercise prompt-building, profile shaping, and the
domain-vocabulary filtering without any real LLM call.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.core.schemas import FileProfile
from app.infrastructure.agents.file_profiler import (
    FileProfiler,
    _FileProfileLLMResponse,
)

# A small framework-domain vocabulary the profiler is constrained to.
_VOCAB = {
    "AuthAgent": "Authentication and session management.",
    "InjectionAgent": "SQL/command/path injection.",
    "CryptoAgent": "Cryptographic storage and transport.",
}


class _FakeClient:
    """Stand-in for LLMClient — returns a canned structured output."""

    def __init__(self, *, parsed=None, error=None, raises=False):
        self._parsed = parsed
        self._error = error
        self._raises = raises
        self.calls: list[str] = []

    async def generate_structured_output(
        self, prompt, response_model, system_prompt=None
    ):
        self.calls.append(prompt)
        if self._raises:
            raise RuntimeError("utility LLM unreachable")
        parsed = None
        if self._parsed is not None and self._error is None:
            parsed = response_model(**self._parsed)
        # profile_file only reads `.parsed_output` / `.error` off the
        # result — a lightweight stand-in avoids depending on the full
        # AgentLLMResult NamedTuple field set.
        return SimpleNamespace(parsed_output=parsed, error=self._error)


def _profile(client, content="def login(): ...") -> FileProfile:
    profiler = FileProfiler(client)
    return asyncio.run(profiler.profile_file("auth/login.py", content, _VOCAB))


def test_profile_has_summary_operations_and_domains():
    client = _FakeClient(
        parsed={
            "summary": "Handles user login and session creation.",
            "security_relevant_operations": [
                "reads request parameters",
                "verifies password",
            ],
            "applicable_domains": ["AuthAgent", "CryptoAgent"],
        }
    )
    profile = _profile(client)
    assert isinstance(profile, FileProfile)
    assert "login" in profile.summary.lower()
    assert "verifies password" in profile.security_relevant_operations
    assert set(profile.applicable_domains) == {"AuthAgent", "CryptoAgent"}


def test_applicable_domains_are_constrained_to_the_vocabulary():
    """Domains the LLM invents that are not real framework domains are
    dropped — the result is always a subset of the vocabulary."""
    client = _FakeClient(
        parsed={
            "summary": "x",
            "security_relevant_operations": [],
            # Two real domains + two hallucinated ones.
            "applicable_domains": [
                "AuthAgent",
                "TotallyMadeUpAgent",
                "InjectionAgent",
                "xss",
            ],
        }
    )
    profile = _profile(client)
    assert set(profile.applicable_domains) == {"AuthAgent", "InjectionAgent"}
    assert all(d in _VOCAB for d in profile.applicable_domains)


def test_profiler_passes_only_vocabulary_names_to_the_model():
    client = _FakeClient(
        parsed={
            "summary": "x",
            "security_relevant_operations": [],
            "applicable_domains": [],
        }
    )
    _profile(client)
    prompt = client.calls[0]
    for name in _VOCAB:
        assert name in prompt


def test_llm_error_yields_a_safe_fallback_profile():
    client = _FakeClient(error="model validation failed after retries")
    profile = _profile(client)
    assert profile.applicable_domains == []
    assert profile.security_relevant_operations == []
    assert "unavailable" in profile.summary.lower()


def test_llm_exception_yields_a_safe_fallback_profile():
    client = _FakeClient(raises=True)
    profile = _profile(client)
    assert isinstance(profile, FileProfile)
    assert profile.applicable_domains == []


def test_llm_response_model_defaults_are_lenient():
    """The raw LLM schema tolerates a sparse response so a terse model
    output doesn't fail validation before the profiler can shape it."""
    resp = _FileProfileLLMResponse(summary="just a summary")
    assert resp.security_relevant_operations == []
    assert resp.applicable_domains == []


# ---------------------------------------------------------------------------
# Repository-map structural grounding — #77
# ---------------------------------------------------------------------------

_OK_RESPONSE = {
    "summary": "x",
    "security_relevant_operations": [],
    "applicable_domains": [],
}


def test_repo_summary_structure_reaches_the_prompt():
    """The file's deterministic tree-sitter imports + symbols are added
    to the profiler prompt as grounding context."""
    client = _FakeClient(parsed=_OK_RESPONSE)
    profiler = FileProfiler(client)
    repo_summary = SimpleNamespace(
        imports=["os", "subprocess", "requests"],
        symbols=[
            SimpleNamespace(name="login", type="function", line_number=12),
            SimpleNamespace(name="UserRepo", type="class", line_number=40),
        ],
    )
    asyncio.run(
        profiler.profile_file(
            "auth/login.py", "def login(): ...", _VOCAB, repo_summary=repo_summary
        )
    )
    prompt = client.calls[0]
    assert "FILE STRUCTURE" in prompt
    assert "subprocess" in prompt and "requests" in prompt
    assert "login" in prompt and "UserRepo" in prompt


def test_profiles_without_a_repo_summary():
    """A file with no repository-map entry still profiles — the
    structural block is simply omitted."""
    client = _FakeClient(parsed=_OK_RESPONSE)
    profiler = FileProfiler(client)
    result = asyncio.run(
        profiler.profile_file("x.py", "code", _VOCAB, repo_summary=None)
    )
    assert isinstance(result, FileProfile)
    assert "FILE STRUCTURE" not in client.calls[0]


def test_empty_repo_summary_omits_the_structure_block():
    """A summary with no imports and no symbols adds nothing."""
    client = _FakeClient(parsed=_OK_RESPONSE)
    profiler = FileProfiler(client)
    empty = SimpleNamespace(imports=[], symbols=[])
    asyncio.run(profiler.profile_file("x.py", "code", _VOCAB, repo_summary=empty))
    assert "FILE STRUCTURE" not in client.calls[0]

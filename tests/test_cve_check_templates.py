"""Nuclei-style checks: what may be stored, and what a replay proves.

The point of a stored check is that the same CVE is tested the same way on every
asset. That only holds if the template is validated once, strictly, and replayed
unchanged — so these tests focus on the validation boundary and the matcher semantics.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.assets import checks

VERSION_TEMPLATE = """
id: CVE-2021-23017-nginx-version
info:
  name: nginx resolver off-by-one (version check)
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words: ["nginx"]
      - type: regex
        part: header
        regex: ["nginx/(1\\\\.1[0-9]\\\\.|1\\\\.20\\\\.0)"]
"""


def test_a_read_only_template_is_accepted():
    template, requests = checks.parse_template(VERSION_TEMPLATE)

    assert template.id.startswith("CVE-2021-23017")
    assert len(requests) == 1
    assert requests[0]["method"] == "GET"
    assert requests[0]["matchers_condition"] == "and"


def test_a_state_changing_method_is_refused():
    bad = VERSION_TEMPLATE.replace("method: GET", "method: POST")

    with pytest.raises(checks.TemplateInvalid) as excinfo:
        checks.parse_template(bad)

    assert "not read-only" in str(excinfo.value)


def test_a_request_body_is_refused():
    bad = VERSION_TEMPLATE.replace(
        '    path:\n      - "{{BaseURL}}/"', '    path:\n      - "{{BaseURL}}/"\n    body: "x=1"'
    )

    with pytest.raises(checks.TemplateInvalid) as excinfo:
        checks.parse_template(bad)

    assert "body" in str(excinfo.value)


def test_an_unsupported_matcher_is_refused():
    bad = VERSION_TEMPLATE.replace("type: word", "type: binary")

    with pytest.raises(checks.TemplateInvalid) as excinfo:
        checks.parse_template(bad)

    assert "not supported" in str(excinfo.value)


def test_a_template_without_matchers_is_refused():
    bad = """
id: CVE-2021-23017-nothing
http:
  - method: GET
    path: ["{{BaseURL}}/"]
"""
    with pytest.raises(checks.TemplateInvalid) as excinfo:
        checks.parse_template(bad)

    assert "no matchers" in str(excinfo.value)


def test_invalid_yaml_is_refused_with_the_reason():
    with pytest.raises(checks.TemplateInvalid) as excinfo:
        checks.parse_template("id: [unclosed")

    assert "not valid YAML" in str(excinfo.value)


def test_matchers_evaluate_over_headers_and_body():
    observation = {
        "status": 200,
        "headers": {"server": "nginx/1.18.0"},
        "body": "<html>ok</html>",
    }

    assert checks._matcher_matches({"type": "word", "part": "header", "words": ["nginx"]}, observation)
    assert checks._matcher_matches(
        {"type": "regex", "part": "header", "regex": ["nginx/1\\.1[0-9]\\."]}, observation
    )
    assert checks._matcher_matches({"type": "status", "status": [200]}, observation)
    assert not checks._matcher_matches(
        {"type": "regex", "part": "header", "regex": ["nginx/2\\."]}, observation
    )


def test_word_matcher_condition_is_honoured():
    observation = {"status": 200, "headers": {"server": "nginx"}, "body": ""}

    assert checks._matcher_matches(
        {"type": "word", "part": "header", "words": ["nginx", "absent"], "condition": "and"},
        observation,
    ) is False
    assert checks._matcher_matches(
        {"type": "word", "part": "header", "words": ["nginx", "absent"], "condition": "or"},
        observation,
    ) is True


def test_replay_runs_the_template_against_the_asset(monkeypatch):
    calls: list[tuple[str, str]] = []

    class FakeResponse:
        status_code = 200
        headers = {"server": "nginx/1.18.0"}
        text = "ok"

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, url, headers=None):
            calls.append((method, url))
            return FakeResponse()

    monkeypatch.setattr(checks.httpx, "AsyncClient", FakeClient)
    services = [
        SimpleNamespace(host="10.0.0.5", port=8443, protocol="https", path=None)
    ]

    observations = asyncio.run(checks.run_template(VERSION_TEMPLATE, services=services))

    assert calls == [("GET", "https://10.0.0.5:8443/")]
    summary = checks.summarise(observations)
    assert summary["matched"] == 1
    assert summary["requests"] == 1


def test_replay_never_leaves_the_asset(monkeypatch):
    calls: list[str] = []

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, url, headers=None):
            calls.append(url)
            raise AssertionError("must not be called for a foreign host")

    monkeypatch.setattr(checks.httpx, "AsyncClient", FakeClient)
    template = VERSION_TEMPLATE.replace("{{BaseURL}}/", "https://evil.example.net/")

    observations = asyncio.run(
        checks.run_template(
            template,
            services=[SimpleNamespace(host="10.0.0.5", port=None, protocol="https", path=None)],
        )
    )

    assert calls == []
    assert any("outside the asset" in str(row.get("error")) for row in observations)


def test_an_asset_without_an_endpoint_is_reported():
    observations = asyncio.run(checks.run_template(VERSION_TEMPLATE, services=[]))
    assert "no endpoint" in str(observations[0].get("error"))

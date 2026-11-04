"""Fetching a CVE that the corpus does not have.

The failure this replaces: an operator pastes an id, the app says "not in the local
corpus", and stops — when the right behaviour is to look it up.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace


from app.assets import enrichment
from app.assets import models as am

NVD_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-23017",
                "descriptions": [{"lang": "en", "value": "nginx resolver off-by-one"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 7.7}, "baseSeverity": "HIGH"}
                    ]
                },
                "references": [
                    {"url": "https://nginx.org/en/security_advisories.html", "tags": ["Vendor Advisory"]}
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "0.6.18",
                                        "versionEndExcluding": "1.20.1",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ]
}


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.urls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, params=None):
        self.urls.append(url)
        return self.response


def test_nvd_response_becomes_a_corpus_record(monkeypatch):
    client = FakeClient(FakeResponse(200, NVD_PAYLOAD))
    monkeypatch.setattr(enrichment.httpx, "AsyncClient", lambda **kw: client)

    outcome = asyncio.run(enrichment.fetch_nvd("CVE-2021-23017"))

    assert outcome is not None
    record, affected = outcome
    assert record.id == "CVE-2021-23017"
    assert record.severity == "high"
    assert record.cvss_score == 7.7
    assert record.references and record.references[0]["url"].startswith("https://nginx.org")
    assert affected and affected[0].product == "nginx"
    assert affected[0].version_end_excl == "1.20.1"


def test_nvd_failure_is_not_an_error(monkeypatch):
    client = FakeClient(FakeResponse(503))
    monkeypatch.setattr(enrichment.httpx, "AsyncClient", lambda **kw: client)

    assert asyncio.run(enrichment.fetch_nvd("CVE-2021-23017")) is None


def test_unreachable_feed_is_not_an_error(monkeypatch):
    class Boom:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            raise OSError("network unreachable")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(enrichment.httpx, "AsyncClient", lambda **kw: Boom())

    assert asyncio.run(enrichment.fetch_nvd("CVE-2021-23017")) is None
    assert asyncio.run(enrichment.fetch_osv("CVE-2021-23017")) is None


def test_model_fallback_is_marked_unverified(monkeypatch):
    class FakeLLM:
        async def generate_structured_output(self, *, prompt, response_model, system_prompt, usage_context):
            return SimpleNamespace(
                parsed_output=response_model(
                    description="nginx resolver off-by-one",
                    affected_products=["nginx"],
                    version_end_excl="1.20.1",
                    cvss_score=7.7,
                    severity="high",
                    cwe="CWE-193",
                    references=["https://nginx.org/en/security_advisories.html"],
                ),
                error=None,
            )

    outcome = asyncio.run(
        enrichment._describe_with_model("CVE-2021-23017", FakeLLM())
    )

    assert outcome is not None
    record, affected = outcome
    assert record.source == "model", "a reconstructed record must not look authoritative"
    assert affected[0].product == "nginx"
    assert affected[0].version_end_excl == "1.20.1"


def test_model_without_a_description_yields_nothing():
    class EmptyLLM:
        async def generate_structured_output(self, **kwargs):
            return SimpleNamespace(parsed_output=None, error="model unavailable")

    assert asyncio.run(enrichment._describe_with_model("CVE-1", EmptyLLM())) is None


def test_aggregate_reports_fetched_unverified_and_missing(monkeypatch):
    async def fake_ensure(cve_id, *, llm=None, allow_model=True):
        return {
            "CVE-1": {"cve_id": "CVE-1", "present": True, "source": "nvd", "fetched": True},
            "CVE-2": {
                "cve_id": "CVE-2",
                "present": True,
                "source": "model",
                "fetched": True,
                "unverified": True,
            },
            "CVE-3": {"cve_id": "CVE-3", "present": False, "source": None, "fetched": False},
        }[cve_id]

    monkeypatch.setattr(enrichment, "ensure_cve", fake_ensure)

    outcome = asyncio.run(enrichment.ensure_cves(["CVE-1", "CVE-2", "CVE-3"]))

    assert [item["cve_id"] for item in outcome["fetched"]] == ["CVE-1", "CVE-2"]
    assert outcome["unverified"] == ["CVE-2"]
    assert outcome["missing"] == ["CVE-3"]


def test_a_record_already_present_is_not_fetched(monkeypatch):
    async def fake_get(_db, cve_id):
        return am.CveRecord(id=cve_id, source="nvd")

    monkeypatch.setattr("sqlalchemy.ext.asyncio.AsyncSession.get", fake_get, raising=False)

    async def no_fetch(*args, **kwargs):
        raise AssertionError("must not hit the network for a CVE already in the corpus")

    monkeypatch.setattr(enrichment, "fetch_nvd", no_fetch)

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, _model, cve_id):
            return am.CveRecord(id=cve_id, source="nvd")

    monkeypatch.setattr(enrichment, "AsyncSessionLocal", lambda: FakeSession())

    outcome = asyncio.run(enrichment.ensure_cve("CVE-2021-23017"))

    assert outcome["present"] is True
    assert outcome["fetched"] is False

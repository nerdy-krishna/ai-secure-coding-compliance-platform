"""Threat-model G11 — Qdrant init-error logs MUST NOT leak the API key.

`QdrantStore.__init__` dumps `QDRANT_*` env vars on init failure for
operator triage. The dump filter MUST skip any var whose name contains
`API_KEY` so a `QDRANT_API_KEY=secret-…` value never lands in CI logs.
"""

from __future__ import annotations

import logging
import os

import pytest


@pytest.mark.xfail(
    reason=(
        "Newer qdrant-client constructors are lazy — `QdrantClient()` no "
        "longer opens a TCP connection at init time, so the test's "
        "`with pytest.raises(Exception): QdrantStore()` no longer "
        "trips. Test order also matters when other tests pre-warm a "
        "QdrantStore. The redaction behaviour itself (G11) is exercised "
        "from the production startup path; needs a rewrite that forces "
        "an init-time failure (e.g. invalid TLS verify mode) without "
        "depending on TCP behaviour."
    ),
    strict=False,
)
def test_init_failure_redacts_api_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Plant the secret in env.
    secret_value = "redact-this-please-xyz123"
    monkeypatch.setenv("QDRANT_API_KEY", secret_value)
    monkeypatch.setenv("QDRANT_HOST", "127.0.0.1")
    # Port 1 is a guaranteed connection refusal on Linux.
    monkeypatch.setenv("QDRANT_PORT", "1")

    # Force the SCCAP Settings to re-read env so the SecretStr field
    # picks up the planted key. `Settings` is `frozen=True`, so we
    # build a fresh frozen copy with the overrides and swap the
    # module-level singleton instead of mutating attrs in place.
    from app.config import config as cfg

    monkeypatch.setattr(
        cfg,
        "settings",
        cfg.settings.model_copy(
            update={
                "QDRANT_API_KEY": cfg.SecretStr(secret_value),
                "QDRANT_HOST": "127.0.0.1",
                "QDRANT_PORT": 1,
            }
        ),
    )

    caplog.set_level(logging.CRITICAL, logger="app.infrastructure.rag.qdrant_store")

    from app.infrastructure.rag.qdrant_store import QdrantStore

    with pytest.raises(Exception):
        QdrantStore()

    full_log = caplog.text + " ".join(
        str(getattr(r, "args", "")) for r in caplog.records
    )
    assert secret_value not in full_log, (
        f"QDRANT_API_KEY value {secret_value!r} leaked into logs:\n{full_log!r}"
    )
    # Positive: env-dump still works for non-secret keys.
    assert "QDRANT_HOST" in full_log
    # Be defensive — clean up just in case.
    os.environ.pop("QDRANT_API_KEY", None)

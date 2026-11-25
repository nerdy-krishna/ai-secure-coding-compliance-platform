"""Which commit is "the version"?

Three stamps exist and they can differ on purpose: what the host deployed, what the API image was
built from, and what the UI bundle was built from. Reporting only the image stamp made a finished
selective update look stale and an unfinished one look finished.
"""

from __future__ import annotations

import importlib

from app.api.v1.routers import system_info


def _reload_with(monkeypatch, **env):
    for key, value in {
        "SCCAP_BUILD_COMMIT": "",
        "SCCAP_DEPLOYED_COMMIT": "",
        **env,
    }.items():
        if value:
            monkeypatch.setenv(key, value)
        else:
            monkeypatch.delenv(key, raising=False)
    return importlib.reload(system_info)


def test_the_deployment_commit_wins_over_the_image_commit(monkeypatch):
    module = _reload_with(
        monkeypatch,
        SCCAP_BUILD_COMMIT="a" * 40,
        SCCAP_DEPLOYED_COMMIT="b" * 40,
    )

    assert module.running_commit() == "b" * 40
    assert module.image_commit() == "a" * 40
    assert module.deployed_commit() == "b" * 40

    module = _reload_with(monkeypatch)
    assert module.running_commit() == ""

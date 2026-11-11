"""Private targets, stoppable checks, and a console that belongs to one scan.

Three things an operator asked for, each with a failure mode worth pinning:

- a private IP is a normal target, and it must not collapse scope to a suffix;
- Stop must reach a check that runs inside a request, not just a job that has a row;
- the activity window must start where the scan starts, not replay the tenant's history.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from app.assets import cancel as cancel_mod
from app.assets import cve_workflow, discovery, service
from app.pentest import scope, ssrf


def test_a_private_target_is_accepted_and_marked():
    guarded = ssrf.validate_target("http://10.0.0.5:8080/app")

    assert guarded.host == "10.0.0.5"
    assert guarded.private is True
    # Tools are still confined to it: the origin is what they may talk to.
    assert guarded.origin == "http://10.0.0.5:8080"


def test_a_bare_host_defaults_to_https():
    assert ssrf.validate_target("192.168.1.10").url == "https://192.168.1.10"
    assert ssrf.validate_target("example.com").url == "https://example.com"


def test_a_public_target_is_not_flagged_private():
    assert ssrf.validate_target("https://example.com").private is False


def test_derived_urls_are_still_confined_to_the_authorised_origin():
    """Allowing a private target must not open the internal network to a tool URL."""

    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.guard_url("http://169.254.169.254/latest/meta-data/")
    # The same address is fine when it *is* the authorised origin.
    assert ssrf.guard_url(
        "http://169.254.169.254/x", allowed_origin="http://169.254.169.254"
    ).host == "169.254.169.254"


def test_an_ip_target_scopes_to_itself():
    base = scope.registrable_domain("10.0.0.5")

    assert base == "10.0.0.5"
    assert scope.in_scope("10.0.0.5", base) is True
    assert scope.in_scope("8.8.0.5", base) is False


def test_a_stop_request_is_seen_by_the_check_and_cleared_on_the_next_run():
    from uuid import uuid4

    tenant = uuid4()
    assert cancel_mod.requested(tenant) is False
    cancel_mod.request(tenant)
    assert cancel_mod.requested(tenant) is True
    with pytest.raises(cancel_mod.CheckStopped):
        cancel_mod.check(tenant)
    cancel_mod.clear(tenant)
    assert cancel_mod.requested(tenant) is False


def test_discovery_stops_between_assets_rather_than_inside_one():
    calls: list = []

    async def fake_discover(asset_id, **kwargs):
        calls.append(asset_id)
        return {"endpoints_probed": 1, "endpoints_open": 1, "fingerprints": [], "outcomes": []}

    stop_after = {"count": 1}

    def should_stop() -> bool:
        return len(calls) >= stop_after["count"]

    original = discovery.discover_asset
    discovery.discover_asset = fake_discover  # type: ignore[assignment]
    try:
        asyncio.run(discovery.discover_assets(["a", "b", "c"], should_stop=should_stop))
    finally:
        discovery.discover_asset = original  # type: ignore[assignment]

    assert calls == ["a"], "the second asset must not be probed after a stop"


def test_the_check_clears_a_previous_stop_and_honours_a_new_one():
    source = inspect.getsource(service.check_cves)

    assert "cancel_mod.clear(tenant_id)" in source
    assert "should_stop=" in source
    assert '"stopped": True' in source


def test_research_ignores_a_stored_model_error_and_asks_again():
    source = inspect.getsource(cve_workflow.research_cve)

    # An HTTP 401 stored as "research" must not be presented as the vulnerability's mechanism.
    assert "_looks_like_error(summary[\"research\"].get(\"mechanism\"))" in source
    assert "research_error" in source

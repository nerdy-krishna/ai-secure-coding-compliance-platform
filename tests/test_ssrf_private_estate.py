"""Private estate versus our own network.

The failure that prompted this: an in-scope subdomain (`intranet.<client>.com`) resolved to 10.x
and `whatweb_scan` was refused with SSRFBlocked. The guard was right about the mechanism and
wrong about the meaning — a client's intranet is the assessment target, not an SSRF.

What must stay true regardless: the platform's own network, loopback and cloud metadata are never
reachable, even from an in-scope name with the declaration switched on.
"""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace

import pytest

from app.pentest import ssrf
from app.pentest.tools.base import RunContext


def resolve_to(monkeypatch, *addresses: str) -> None:
    ips = {ipaddress.ip_address(address) for address in addresses}
    monkeypatch.setattr(ssrf, "_resolve_ips", lambda _host: ips)


def test_an_in_scope_host_may_resolve_private_when_the_estate_says_so(monkeypatch):
    resolve_to(monkeypatch, "10.20.30.40")

    guarded = ssrf.guard_url(
        "https://intranet.client.example/",
        allowed_origin="https://www.client.example",
        allow_private_estate=True,
    )

    assert guarded.host == "intranet.client.example"


def test_without_the_declaration_it_is_still_refused_with_an_actionable_reason(monkeypatch):
    resolve_to(monkeypatch, "10.20.30.40")

    with pytest.raises(ssrf.SSRFBlocked) as excinfo:
        ssrf.guard_url("https://intranet.client.example/")

    message = str(excinfo.value)
    assert "resolves to private address" in message
    assert "the estate resolves to private addresses" in message


def test_cloud_metadata_is_refused_even_with_the_declaration(monkeypatch):
    resolve_to(monkeypatch, "169.254.169.254")

    with pytest.raises(ssrf.SSRFBlocked) as excinfo:
        ssrf.guard_url("http://169.254.169.254/", allow_private_estate=True)

    assert "metadata services live there" in str(excinfo.value)


def test_loopback_is_refused_even_with_the_declaration(monkeypatch):
    resolve_to(monkeypatch, "127.0.0.1")

    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.guard_url("http://localhost/", allow_private_estate=True)


def test_the_engines_own_network_is_refused_even_with_the_declaration(monkeypatch):
    """An in-scope name resolving onto the compose bridge would attack the platform."""
    resolve_to(monkeypatch, "172.18.0.2")
    monkeypatch.setattr(
        ssrf, "_engine_nets", lambda: (ipaddress.ip_network("172.18.0.0/24"),)
    )

    with pytest.raises(ssrf.SSRFBlocked) as excinfo:
        ssrf.guard_url("https://intranet.client.example/", allow_private_estate=True)

    assert "the network this engine runs on" in str(excinfo.value)


def test_an_operator_can_name_extra_ranges_to_protect(monkeypatch):
    resolve_to(monkeypatch, "192.168.5.5")
    monkeypatch.setenv("PENTEST_SSRF_DENY_CIDRS", "192.168.0.0/16")
    monkeypatch.setattr(ssrf, "_engine_nets", lambda: (ipaddress.ip_network("192.168.0.0/16"),))

    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.guard_url("https://intranet.client.example/", allow_private_estate=True)


def test_public_resolution_is_unaffected():
    # No DNS in tests: a literal public address needs none.
    grouped = ssrf.guard_url("https://93.184.216.34/", allow_private_estate=False)

    assert grouped.host == "93.184.216.34"


def test_raw_tcp_tools_get_the_same_exemption(monkeypatch):
    resolve_to(monkeypatch, "10.20.30.40")

    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.assert_public_resolution("intranet.client.example")

    ssrf.assert_public_resolution(
        "intranet.client.example",
        allow_origin="www.client.example",
        allow_private_estate=True,
    )


def context(*, allow_private_estate: bool, allow_subdomains: bool = True) -> RunContext:
    return RunContext(
        run_id="00000000-0000-0000-0000-000000000001",
        target=SimpleNamespace(
            host="www.client.example",
            origin="https://www.client.example",
            scheme="https",
            port=None,
            url="https://www.client.example/",
        ),
        box_type="black",
        allow_subdomains=allow_subdomains,
        allow_private_estate=allow_private_estate,
    )


def test_the_context_only_allows_private_inside_the_scope(monkeypatch):
    resolve_to(monkeypatch, "10.20.30.40")
    ctx = context(allow_private_estate=True)

    # In scope: allowed.
    assert ctx.guard("https://intranet.client.example/").host == "intranet.client.example"
    # Out of scope: refused before the address even matters.
    with pytest.raises(ssrf.SSRFBlocked):
        ctx.guard("https://intranet.other.example/")


def test_the_declaration_does_not_widen_a_fixed_scope(monkeypatch):
    resolve_to(monkeypatch, "10.20.30.40")
    ctx = context(allow_private_estate=True, allow_subdomains=False)

    with pytest.raises(ssrf.SSRFBlocked):
        ctx.guard("https://intranet.client.example/")

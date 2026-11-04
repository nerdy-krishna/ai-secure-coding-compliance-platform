"""Active discovery: what an asset is, before asking what affects it.

The failure these cover is the one an operator sees: three IPs, one CVE, and an
instant "nothing found" because nothing was ever looked at.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

from app.assets import discovery


def test_looks_like_host_separates_ips_hostnames_and_labels():
    assert discovery.looks_like_host("10.0.0.5")
    assert discovery.looks_like_host("192.168.1.20")
    assert discovery.looks_like_host("portal.example.com")
    assert not discovery.looks_like_host("Customer portal")
    assert not discovery.looks_like_host("payments-api")
    assert not discovery.looks_like_host("")
    # A name that merely contains a dot is not automatically a host.
    assert not discovery.looks_like_host("billing v2.0")


def test_candidate_targets_covers_web_ports_for_an_unfingerprinted_host():
    service = SimpleNamespace(host="10.0.0.5", port=None, protocol="https")

    targets = discovery.candidate_targets([service], scan_ports=True)

    assert ("10.0.0.5", 443, "https") in targets
    assert ("10.0.0.5", 80, "http") in targets
    assert len(targets) >= 4


def test_candidate_targets_respects_a_recorded_port():
    service = SimpleNamespace(host="10.0.0.5", port=8443, protocol="https")

    targets = discovery.candidate_targets([service], scan_ports=False)

    assert targets == [("10.0.0.5", 8443, "https")]


def test_candidate_targets_are_unique():
    services = [
        SimpleNamespace(host="10.0.0.5", port=443, protocol="https"),
        SimpleNamespace(host="10.0.0.5", port=None, protocol="https"),
    ]

    targets = discovery.candidate_targets(services, scan_ports=True)

    assert len(targets) == len(set(targets))


def test_http_fingerprint_reads_the_server_header():
    response = SimpleNamespace(
        headers={"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1.2"},
        text="<html><head><title>Portal</title></head></html>",
    )

    product, version, banner = discovery._fingerprint_from_http(response)

    assert product.lower() == "nginx"
    assert version == "1.18.0"
    assert "nginx/1.18.0" in banner


def test_http_fingerprint_prefers_the_origin_over_the_proxy():
    response = SimpleNamespace(
        headers={"server": "BaseHTTP/0.6 Python/3.12.16, nginx/1.18.0"},
        text="ok",
    )

    product, version, banner = discovery._fingerprint_from_http(response)

    assert product.lower() == "nginx"
    assert version == "1.18.0"
    assert "BaseHTTP" in banner, "the full banner is kept for later matching"


def test_http_fingerprint_falls_back_to_the_generator_meta():
    response = SimpleNamespace(
        headers={},
        text='<html><head><meta name="generator" content="WordPress 6.2.1"></head></html>',
    )

    product, version, _banner = discovery._fingerprint_from_http(response)

    assert product == "WordPress"
    assert version == "6.2.1"


def test_version_parsing_handles_banners_without_a_version():
    assert discovery._parse_version("OpenSSH_9.3p1 Ubuntu") == "9.3p1"
    assert discovery._parse_version("vsftpd") is None


def test_unreachable_host_is_recorded_not_raised(monkeypatch):
    async def boom(*args, **kwargs):
        raise OSError("network unreachable")

    monkeypatch.setattr(socket, "create_connection", boom)
    outcome = __import__("asyncio").run(discovery._probe_http("10.255.255.1", 80, "http"))
    assert outcome is not None
    assert outcome.get("error")


def test_unknown_cve_is_reported_not_silently_zero():
    """`check_cves` must distinguish "not in the corpus" from "nothing matched".

    The distinction is the whole point of the report: three IPs, one CVE that was
    never imported, and a zero that reads like a clean result.
    """
    import inspect

    from app.assets import service

    source = inspect.getsource(service.check_cves)
    assert "unknown_cves" in source
    # Enrichment runs before matching, so a fetched CVE has ranges to match against.
    assert "ensure_cves" in source
    assert source.index("ensure_cves") < source.index("match_cves_for_tenant")


def test_the_asset_name_is_offered_as_a_host_header(monkeypatch):
    """A CDN answers its own name, not the address: that is the whole point."""
    monkeypatch.setattr(discovery, "_reverse_dns", lambda host: [])

    candidates = discovery.host_header_candidates(
        "125.21.247.160", asset_name="quoquo.tvsmotor.com"
    )

    assert "quoquo.tvsmotor.com" in candidates
    assert "125.21.247.160" not in candidates, "the bare address is already the default"


def test_a_label_that_is_not_a_hostname_is_not_offered(monkeypatch):
    monkeypatch.setattr(discovery, "_reverse_dns", lambda host: [])

    assert discovery.host_header_candidates("10.0.0.5", asset_name="billing v2") == []


def test_certificate_names_and_reverse_dns_are_offered(monkeypatch):
    monkeypatch.setattr(discovery, "_reverse_dns", lambda host: ["edge.example.net"])

    candidates = discovery.host_header_candidates(
        "10.0.0.5", extra=["www.example.net", "edge.example.net"]
    )

    assert candidates == ["edge.example.net", "www.example.net"]


def test_the_transcript_shows_the_command_that_ran():
    http_probe = {
        "host": "125.21.247.160",
        "port": 443,
        "protocol": "https",
        "host_header": "quoquo.tvsmotor.com",
        "status": 200,
        "banner": "nginx/1.18.0",
        "product": "nginx",
        "version": "1.18.0",
        "length": 1554,
        "title": "Home",
    }

    command = discovery.command_line(http_probe)
    response = discovery.response_line(http_probe)

    assert command.startswith("curl")
    assert "-H 'Host: quoquo.tvsmotor.com'" in command
    assert "https://125.21.247.160" in command
    assert "HTTP 200" in response and "nginx" in response


def test_a_banner_probe_is_shown_as_a_tcp_connection():
    probe = {"host": "10.0.0.5", "port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.3"}

    assert discovery.command_line(probe) == "nc -w 3 10.0.0.5 22"
    assert "OpenSSH" in discovery.response_line(probe)


def test_a_failed_probe_says_why():
    assert discovery.response_line({"host": "h", "port": 1, "error": "TimeoutError"}) == "    ! TimeoutError"


def test_web_ports_cover_more_than_the_usual_two():
    ports = {port for port, _ in discovery.WEB_PORTS}

    assert {80, 443, 8080, 8443} <= ports
    assert len(ports) >= 10, "a management console rarely lives on 80/443 alone"

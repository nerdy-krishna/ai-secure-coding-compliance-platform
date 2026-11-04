"""The scope ledger: what a call covers, and what happens when it is covered twice.

The bug this exists for: `nmap` and `nmap --ports top-1000` were different work as far
as the old exact-argument dedupe was concerned, and `sqlmap --level=1` then `--level=3`
looked like two findings attempts. A scope is what the call establishes, not how hard it
tried.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.pentest import scope_ledger as led
from app.pentest.tools import build_registry

registry = build_registry()


def scope(tool: str, args: dict, auth: str = "anonymous") -> dict:
    return led.scope_for(registry.spec(tool), args, auth_state=auth)


def test_effort_knobs_do_not_change_scope():
    assert scope("nmap_scan", {"host": "h", "ports": "top-1000"}) == scope(
        "nmap_scan", {"host": "h", "ports": "top-1000", "timing": "T4"}
    )
    assert scope("sqlmap_scan", {"path": "/login", "level": 1}) == scope(
        "sqlmap_scan", {"path": "/login", "level": 5, "risk": 3}
    )


def test_different_surface_is_a_different_scope():
    assert scope("sqlmap_scan", {"path": "/login"}) != scope("sqlmap_scan", {"path": "/search"})


def test_list_arguments_are_order_independent():
    """`-tags cve,exposure` and `-tags exposure,cve` are the same sweep."""
    assert scope("nuclei_scan", {"target": "/", "tags": ["exposure", "cve"]}) == scope(
        "nuclei_scan", {"target": "/", "tags": ["cve", "exposure"]}
    )


def test_paths_normalise_against_the_target_origin():
    assert scope("http_request", {"url": "https://example.com/a?id=1"}) == scope(
        "http_request", {"url": "/a?id=1"}
    )


def test_auth_state_is_part_of_the_scope():
    anonymous = scope("http_request", {"url": "/account"})
    authenticated = scope("http_request", {"url": "/account"}, auth="authenticated")

    assert anonymous != authenticated
    assert "authenticated" in led.describe_scope(authenticated)


def test_scope_key_is_bounded_and_stable():
    args = {"data": {"field": "x" * 2000}}
    first = led.scope_key("http_request", scope("http_request", args))
    second = led.scope_key("http_request", scope("http_request", args))

    assert first == second
    assert len(first) <= led.MAX_SCOPE_KEY_CHARS


def test_the_repeat_message_says_where_the_output_is():
    row = SimpleNamespace(
        tool="nuclei_scan",
        step=7,
        runs=2,
        digest="14 matches across 3 hosts",
        artifact_id="8f14e45f-ceea-467a-9a3e-1b1c2d3e4f50",
    )

    message = led.repeat_message(
        tool="nuclei_scan", scope={"host": "example.com", "auth": "anonymous"}, row=row
    )

    assert "NOT RUN" in message
    assert "nuclei_scan" in message
    assert "at step 7" in message
    assert "art=8f14e45f" in message
    assert "queries" in message, "the model must be told it can filter instead of re-running"
    assert "rerun_reason" in message


def test_querying_a_payload_returns_only_what_was_asked_for():
    payload = {
        "results": [
            {"url": "/admin", "status": 200},
            {"url": "/static/app.js", "status": 200},
            {"url": "/admin/login", "status": 302},
        ]
    }

    answer = led.query_artifact(payload, path="results", contains="admin")

    assert answer["total"] == 3
    assert answer["matched"] == 2
    assert all("admin" in row["url"] for row in answer["rows"])


def test_query_supports_regex_and_limit():
    payload = {"open_ports": [{"port": 22}, {"port": 443}, {"port": 8080}]}

    answer = led.query_artifact(payload, path="open_ports", regex=r'"port": 4', limit=1)

    assert answer["matched"] == 1
    assert answer["rows"][0]["port"] == 443


def test_query_with_a_bad_regex_reports_it():
    answer = led.query_artifact({"a": 1}, regex="[unclosed")

    assert "error" in answer


def test_ledger_render_groups_by_host():
    rows = [
        SimpleNamespace(tool="whatweb_scan", runs=1, scope={"host": "a.example"}),
        SimpleNamespace(tool="nmap_scan", runs=2, scope={"host": "a.example"}),
        SimpleNamespace(tool="nuclei_scan", runs=1, scope={"host": "b.example"}),
    ]

    text = led.render_ledger(rows)

    assert "Scope already covered" in text
    assert "a.example" in text and "nmap_scan×2" in text
    assert "b.example" in text


def test_ledger_render_is_empty_without_history():
    assert led.render_ledger([]) == ""


def test_a_declared_reason_is_what_permits_a_rerun():
    """The ledger accepts a repeat only when the tool's contract lists the reason."""
    spec = registry.spec("nuclei_scan")

    assert "authenticated" in spec.rerun_on
    assert "new_templates" in spec.rerun_on
    # sqlmap says nothing about templates: re-running it for that reason is not a thing.
    assert "new_templates" not in registry.spec("sqlmap_scan").rerun_on


def test_one_shot_tools_have_no_effort_escape():
    """subdomain enumeration cannot be made 'new' by trying harder."""
    spec = registry.spec("subdomain_enum")

    assert spec.rerun_on == ("new_host",)
    assert scope("subdomain_enum", {"domain": "example.com", "max_candidates": 4000}) == scope(
        "subdomain_enum", {"domain": "example.com", "max_candidates": 9000}
    )


def test_browser_steps_are_never_replayed_from_the_ledger():
    """A browser is a stateful sequence: replaying a click would be a lie."""
    for name in ("browser_click", "browser_fill", "browser_navigate", "browser_submit"):
        assert registry.spec(name).cache_scope is False


def test_the_catalogue_tells_the_model_the_scope_contract():
    entry = next(item for item in registry.catalog(frozenset()) if item["name"] == "nuclei_scan")

    assert entry["scope"] == ["host", "target", "tags", "templates"]
    assert "authenticated" in entry["rerun_on"]

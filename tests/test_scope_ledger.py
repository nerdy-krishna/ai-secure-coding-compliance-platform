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


def test_the_agent_announces_each_call_with_its_arguments_and_call_id(monkeypatch):
    """The monitor needs the exact arguments and a live status, not "tool start X"."""
    import asyncio
    import uuid as uuid_mod
    from types import SimpleNamespace

    from app.pentest import agent as agent_mod
    from app.pentest import artifacts as artifacts_mod
    from app.pentest import memory as memory_mod
    from app.pentest import plan as plan_mod
    from app.pentest import steering as steering_mod
    from app.pentest.tools.base import RunContext, ToolResult

    emitted: list[tuple[str, dict]] = []

    async def noop(*args, **kwargs):
        return None

    async def empty_list(*args, **kwargs):
        return []

    async def empty_text(*args, **kwargs):
        return ""

    async def empty_counts(*args, **kwargs):
        return {}

    async def zero(*args, **kwargs):
        return 0

    async def directives(*args, **kwargs):
        return "", []

    async def read_artifact(*args, **kwargs):
        return None

    async def collect(kind, payload):
        emitted.append((kind, payload))

    monkeypatch.setattr(steering_mod, "render_for_prompt", directives)
    for name in ("mark_applied", "clear_pinned_tool", "apply_tool_policy", "note_probe"):
        monkeypatch.setattr(steering_mod, name, noop)
    monkeypatch.setattr(steering_mod, "looping_tools", empty_counts)
    monkeypatch.setattr(memory_mod, "load", lambda *a, **k: _await(("", [])))
    monkeypatch.setattr(memory_mod, "record", zero)
    monkeypatch.setattr(memory_mod, "total_tokens", zero)
    monkeypatch.setattr(memory_mod, "split_for_compaction", lambda *a, **k: _await(([], 0)))
    monkeypatch.setattr(memory_mod, "apply_compaction", zero)
    monkeypatch.setattr(memory_mod, "recent_probes", empty_list)
    monkeypatch.setattr(plan_mod, "counts", empty_counts)
    monkeypatch.setattr(plan_mod, "open_items", empty_list)
    monkeypatch.setattr(plan_mod, "replace_plan", zero)
    monkeypatch.setattr(plan_mod, "update_items", zero)
    monkeypatch.setattr(plan_mod, "render_for_prompt", empty_text)
    monkeypatch.setattr(artifacts_mod, "save", lambda *a, **k: _await(None))
    monkeypatch.setattr(artifacts_mod, "read", read_artifact)
    monkeypatch.setattr(artifacts_mod, "recent", empty_list)
    monkeypatch.setattr(led, "lookup", lambda *a, **k: _await(None))
    monkeypatch.setattr(led, "record", noop)
    monkeypatch.setattr(led, "covered_scopes", empty_list)
    monkeypatch.setattr(led, "render_ledger", lambda *a, **k: "")
    # The lead queue also renders from the database; this test is about the call events.
    monkeypatch.setattr(agent_mod.lead_queue, "render_for_prompt", lambda db, run_id: _await(""))
    monkeypatch.setattr(agent_mod.PentestAgent, "_refresh_policy", noop)
    monkeypatch.setattr(agent_mod.PentestAgent, "_open_lead_count", zero)
    monkeypatch.setattr(agent_mod.PentestAgent, "_claim_leads", noop)
    monkeypatch.setattr(agent_mod.PentestAgent, "_queue_tool_leads", zero)
    monkeypatch.setattr(agent_mod, "record_findings", zero)

    class Recorder:
        def has(self, name):
            return True

        def spec(self, name):
            return registry.spec(name)

        def catalog(self, disabled):
            return registry.catalog(disabled)

        async def invoke(self, name, ctx, args):
            return ToolResult(ok=True, output={"matches": []}, raw="")

    class LLM:
        def __init__(self):
            self.turn = 0

        async def generate_structured_output(
            self, *, prompt, response_model, system_prompt, usage_context
        ):
            if response_model is agent_mod.PentestPlan:
                return SimpleNamespace(
                    parsed_output=agent_mod.PentestPlan(
                        assessment="x", hypotheses=[], first_actions=[]
                    ),
                    error=None,
                )
            self.turn += 1
            if self.turn == 1:
                return SimpleNamespace(
                    parsed_output=agent_mod.NextAction.model_validate(
                        {
                            "reasoning": "sweep",
                            "calls": [
                                {
                                    "tool": "nuclei_scan",
                                    "arguments": {"target": "/", "tags": ["cve"]},
                                }
                            ],
                        }
                    ),
                    error=None,
                )
            return SimpleNamespace(
                parsed_output=agent_mod.NextAction.model_validate(
                    {"reasoning": "done", "done": True, "summary": "ok"}
                ),
                error=None,
            )

    ctx = RunContext(
        run_id=uuid_mod.uuid4(),
        target=SimpleNamespace(url="https://example.com", host="example.com"),
        box_type="black",
        emit=collect,
    )

    asyncio.run(agent_mod.PentestAgent(ctx, Recorder(), LLM(), recon_summary={}).run())

    starts = [payload for kind, payload in emitted if kind == "tool_start"]
    results = [payload for kind, payload in emitted if kind == "tool_result"]
    assert starts, "every tool call must be announced, whatever the tool does itself"
    assert starts[0]["arguments"] == {"target": "/", "tags": ["cve"]}
    assert starts[0]["scope"]["target"] == "/"
    assert starts[0]["call_id"]
    assert results and results[0]["call_id"] == starts[0]["call_id"], (
        "the result must pair with its call, so the row can show a finish time"
    )


def _await(value):
    async def inner():
        return value

    return inner()

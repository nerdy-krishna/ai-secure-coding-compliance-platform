"""Validation runs: the code scan's findings are the mission, and every one gets a verdict.

The rules worth pinning: a validation run cannot exist without the scan it settles, its toolset
excludes the tools that widen the estate, an `exploitable` verdict needs evidence, and a verdict
lands in the coverage ledger so the run cannot close on an unvalidated finding.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.pentest import validation


def test_cwe_maps_to_the_engines_own_classes():
    assert validation.class_for("CWE-89") == "sqli"
    assert validation.class_for("79") == "xss"
    assert validation.class_for("CWE-639") == "idor"
    assert validation.class_for("CWE-918") == "ssrf"
    assert validation.class_for("CWE-22") == "lfi"
    # An unmapped CWE becomes `other` rather than a guess that aims the wrong playbook.
    assert validation.class_for("CWE-999999") == "other"
    assert validation.class_for(None) == "other"


def test_the_verdict_to_coverage_mapping_covers_every_verdict():
    assert set(validation._COVERAGE_OUTCOME) == set(validation.VERDICTS)
    # Only a proven exploit counts as reported; an unreached finding is not "clean".
    assert validation._COVERAGE_OUTCOME[validation.EXPLOITABLE] == "reported"
    assert validation._COVERAGE_OUTCOME[validation.NOT_EXPLOITABLE] == "ruled_out"
    assert validation._COVERAGE_OUTCOME[validation.INCONCLUSIVE] == "needs_follow_up"


def test_the_validation_toolset_excludes_the_estate_tools():
    assert "nmap_scan" in validation.VALIDATION_DISABLED_TOOLS
    assert "subdomain_enum" in validation.VALIDATION_DISABLED_TOOLS
    # The app-level tools stay: they are how a finding is settled.
    assert "http_request" not in validation.VALIDATION_DISABLED_TOOLS
    assert "sqlmap_scan" not in validation.VALIDATION_DISABLED_TOOLS


def test_the_findings_block_names_each_finding_with_its_id():
    finding = validation.CodeFinding(
        id=42,
        title="SQL injection in order lookup",
        cwe="89",
        file_path="app/orders.py",
        line=118,
        severity="high",
        snippet="cursor.execute(f\"SELECT * FROM orders WHERE id={order_id}\")",
        klass="sqli",
    )

    rendered = validation.render_findings([finding])

    assert "`42`" in rendered
    assert "sql injection in order lookup" in rendered.lower()
    assert "app/orders.py:118" in rendered
    assert "execute" in rendered


def test_the_validation_doctrine_says_what_the_run_is_for():
    text = validation.VALIDATION_DOCTRINE

    assert "Every step answers a finding" in text
    assert "record_validation" in text
    # The four verdicts are named so the model does not invent a fifth.
    for verdict in validation.VERDICTS:
        assert verdict in text


def test_a_validation_run_needs_the_scan_it_settles():
    """Without it the run would silently become an ordinary assessment."""
    import inspect

    from app.pentest import service

    source = inspect.getsource(service.create_run)
    assert "a validation run needs the code scan" in source
    assert "MODE_VALIDATION" in source


def test_recording_an_exploitable_verdict_without_evidence_is_refused():
    from app.pentest.tools import validation_tools

    ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", tenant_id=None)

    result = asyncio.run(
        validation_tools.record_validation(
            ctx, {"finding_id": 1, "verdict": "exploitable", "method": "sqlmap"}
        )
    )

    assert result.ok is False
    assert "needs evidence" in result.error


def test_an_unknown_verdict_is_refused_with_the_list():
    from app.pentest.tools import validation_tools

    ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", tenant_id=None)

    result = asyncio.run(
        validation_tools.record_validation(ctx, {"finding_id": 1, "verdict": "probably"})
    )

    assert result.ok is False
    assert "exploitable" in result.error and "blocked" in result.error


def test_the_two_validation_tools_are_registered():
    from app.pentest.tools import build_registry

    registry = build_registry()

    assert registry.spec("list_code_findings") is not None
    assert registry.spec("record_validation") is not None


def test_the_whitebox_scan_list_compares_upper_case_statuses():
    """The dropdown was empty because it filtered `completed` against `COMPLETED`."""
    import inspect

    from app.api.v1.routers import pentest as pentest_router

    source = inspect.getsource(pentest_router.list_whitebox_scans)
    assert "STATUS_COMPLETED" in source
    assert '"completed"' not in source


def test_the_scanned_code_is_read_from_the_stored_snapshot(monkeypatch):
    """The run reads the bytes the scanner read, not a fresh clone."""
    from app.pentest import code_access

    files = {
        "app/orders.py": "def order(id):\n    return db.execute(f'SELECT * FROM o WHERE id={id}')\n",
        "web/src/pages/Order.tsx": "fetch(`/api/orders/${id}`)\n",
    }
    mapping = {path: f"hash-{index}" for index, path in enumerate(files)}
    contents = {mapping[path]: content for path, content in files.items()}

    async def fake_map(_scan_id):
        return mapping

    async def fake_contents(hashes):
        return {key: value for key, value in contents.items() if key in set(hashes)}

    monkeypatch.setattr(code_access, "_file_map", fake_map)
    monkeypatch.setattr(code_access, "_contents", fake_contents)

    window = asyncio.run(code_access.read_file("scan", "app/orders.py", start=1, end=2))
    assert "SELECT * FROM o" in window["text"]
    assert window["total_lines"] == 2
    # Numbered, so the agent can talk about a line.
    assert window["text"].startswith("    1\tdef order")

    hit = asyncio.run(code_access.search("scan", "/api/orders"))
    assert hit["hits"] and hit["hits"][0]["path"] == "web/src/pages/Order.tsx"
    assert "fetch(" in hit["hits"][0]["text"]


def test_a_path_cannot_escape_the_snapshot():
    for bad in ("../etc/passwd", "app/../../secret", "/../x", "", "."):
        assert_code_access_rejects(bad)


def assert_code_access_rejects(path: str) -> None:
    from app.pentest import code_access

    raised = False
    try:
        code_access.normalise_path(path)
    except ValueError:
        raised = True
    assert raised, path


def test_the_code_tools_need_a_scan():
    from app.pentest.tools import code_tools

    ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", whitebox_scan_id=None)

    result = asyncio.run(code_tools.read_code(ctx, {"path": "app/orders.py"}))

    assert result.ok is False
    assert "no code scan" in result.error


def test_the_selection_is_honoured_when_loading_findings():
    import inspect

    from app.pentest import validation as validation_mod

    source = inspect.getsource(validation_mod.load_code_findings)
    assert "only" in source and "in_(only)" in source


def test_a_verdict_on_a_finding_outside_the_selection_is_refused():
    import inspect

    from app.pentest import validation as validation_mod

    source = inspect.getsource(validation_mod.record_verdict)
    assert "not part of this run's selection" in source


def test_the_code_tools_are_registered():
    from app.pentest.tools import build_registry

    registry = build_registry()

    for name in ("list_code_files", "search_code", "read_code"):
        assert registry.spec(name) is not None, name


def test_the_findings_list_is_filtered_and_counted_on_the_server():
    """Why only critical and high appeared: the endpoint returned the first page by severity.

    A 2,400-finding report has hundreds of criticals; sorting by severity and taking 200 rows
    shows only those, and the picker had no way to say so or to reach the rest.
    """
    import inspect

    from app.pentest import validation as validation_mod

    source = inspect.getsource(validation_mod.load_code_findings)
    assert "offset" in source and "severity" in source and "klass" in source and "query" in source

    counts_source = inspect.getsource(validation_mod.code_finding_counts)
    assert "by_severity" in counts_source and "by_class" in counts_source


def test_the_severity_filter_matches_any_capitalisation():
    from app.pentest.validation import _severity_filter

    values = _severity_filter("Critical")
    assert "critical" in values and "CRITICAL" in values and "Critical" in values


def test_a_validation_run_does_not_run_the_fixed_recon_pass():
    """Recon tools are chosen per finding; the automated pass would bury the thing being tested."""
    import inspect

    from app.pentest import engine

    source = inspect.getsource(engine.RunExecutor)
    assert "_validation_preflight" in source
    assert 'mode", "assessment") == "validation"' in source
    # The fixed pass is still there for ordinary assessments.
    assert "run_recon(ctx, registry)" in source


def test_the_status_view_names_what_it_is_working_on():
    import inspect

    from app.pentest import validation as validation_mod

    source = inspect.getsource(validation_mod.current_focus)
    assert "last_action" in source and "planned_method" in source
    # A run with nothing pending has no current focus.
    assert asyncio.run(validation_mod.current_focus("run", [])) is None

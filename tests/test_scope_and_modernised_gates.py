"""The scope choice, and the legacy gates that used to outrank the new methodology.

Two things this pins:

- with subdomain expansion off, the scope is the target host: a sibling host is refused and
  enumeration is not run;
- the coverage ledger decides whether a run is finished. The lead queue and the plan help it
  make progress, but they no longer outrank it, and a model that keeps insisting cannot hold a
  run open forever.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.pentest.agent import PentestAgent
from app.pentest.tools.base import RunContext


def context(host: str = "www.example.com", *, allow_subdomains: bool) -> RunContext:
    return RunContext(
        run_id="00000000-0000-0000-0000-000000000001",
        target=SimpleNamespace(
            host=host,
            origin=f"https://{host}",
            scheme="https",
            port=None,
            url=f"https://{host}/",
        ),
        box_type="black",
        allow_subdomains=allow_subdomains,
    )


def test_with_subdomains_off_the_target_is_the_whole_scope():
    ctx = context(allow_subdomains=False)

    assert ctx.allows_host("www.example.com") is True
    assert ctx.allows_host("api.example.com") is False, "a sibling is outside a fixed scope"
    assert ctx.allows_host("example.com") is False


def test_with_subdomains_on_the_estate_is_in_scope():
    ctx = context(allow_subdomains=True)

    assert ctx.allows_host("api.example.com") is True
    assert ctx.allows_host("deep.api.example.com") is True
    assert ctx.allows_host("other.example.net") is False


def test_a_discovered_host_cannot_widen_a_fixed_scope():
    ctx = context(allow_subdomains=False)

    assert ctx.add_scope_host("api.example.com") is False
    assert ctx.scope_hosts == set(), "a refused host is not remembered as in scope"
    assert ctx.all_hosts() == ["www.example.com"]


def test_a_fixed_scope_refuses_a_url_on_another_host_with_the_reason():
    ctx = context(allow_subdomains=False)

    with pytest.raises(ValueError) as excinfo:
        ctx.scoped_url("https://api.example.com/admin")
    assert "outside the authorised scope" in str(excinfo.value)

    assert ctx.scoped_url("/admin") == "https://www.example.com/admin"


def test_a_fixed_scope_says_why_in_the_error():
    ctx = context(allow_subdomains=False)

    with pytest.raises(ValueError) as excinfo:
        ctx.scoped_origin("api.example.com")
    assert "subdomain expansion is off" in str(excinfo.value)


def test_the_lead_queue_no_longer_outranks_a_settled_ledger():
    """The old gate refused `done` up to three times on open leads alone.

    Every observation queues a lead, so on a real target that gate could never be satisfied —
    and a run with every planned class settled was still being refused. The ledger now decides.
    """
    import inspect

    source = inspect.getsource(PentestAgent._refuse_premature_done)

    # Coverage is evaluated before the queues in the caller, and the refusal helper starts with
    # the queue only as a way to settle it.
    assert "settled = not uncovered" in inspect.getsource(PentestAgent.run)
    assert "open_leads_hint" in source
    assert "coverage still has" in source


def test_a_model_cannot_hold_a_run_open_forever():
    assert PentestAgent.MAX_DONE_REFUSALS >= 1
    import inspect

    source = inspect.getsource(PentestAgent._refuse_premature_done)
    assert "self._done_total > self.MAX_DONE_REFUSALS" in source
    assert "the gaps stay in the coverage ledger" in source


def test_the_plan_can_be_revisited_without_losing_what_was_learned():
    assert PentestAgent.MAX_REPLANS >= 1
    import inspect

    source = inspect.getsource(PentestAgent._write_plan)
    # A re-plan does not early-return on an existing plan; replace_plan is idempotent per pair.
    assert "not replan" in source and "open_total" in source


def test_re_planning_is_bounded():
    import inspect

    source = inspect.getsource(PentestAgent.run)
    assert "self._replans < self.MAX_REPLANS" in source

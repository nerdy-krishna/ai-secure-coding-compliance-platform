"""Unit tests for the finding-disposition state machine (PRD #96 / #97).

Pure-function tests — no DB, no fixtures. Exercises the observable
behavior: which values are valid, which transitions are allowed, which
ones demand a justification note, and which states are scoreable.
"""

import pytest

from app.shared.lib import finding_disposition as fd


def test_default_disposition_is_open():
    assert fd.DEFAULT_DISPOSITION == "open"


def test_dispositions_set_has_exactly_five_states():
    assert fd.DISPOSITIONS == {
        "open",
        "confirmed",
        "false_positive",
        "remediated",
        "risk_accepted",
    }


@pytest.mark.parametrize(
    "value", ["open", "confirmed", "false_positive", "remediated", "risk_accepted"]
)
def test_is_valid_disposition_accepts_known_states(value):
    assert fd.is_valid_disposition(value) is True


@pytest.mark.parametrize("value", ["", "OPEN", "wontfix", "duplicate", "fixed"])
def test_is_valid_disposition_rejects_unknown_states(value):
    assert fd.is_valid_disposition(value) is False


def test_scoreable_states_are_open_and_confirmed():
    assert fd.SCOREABLE == {"open", "confirmed"}


def test_non_scoreable_states_drop_from_risk():
    assert fd.NON_SCOREABLE == {"false_positive", "remediated", "risk_accepted"}


@pytest.mark.parametrize("state", ["open", "confirmed"])
def test_is_scoreable_true_for_open_and_confirmed(state):
    assert fd.is_scoreable(state) is True


@pytest.mark.parametrize("state", ["false_positive", "remediated", "risk_accepted"])
def test_is_scoreable_false_for_resolved_states(state):
    assert fd.is_scoreable(state) is False


def test_is_scoreable_fails_open_for_unknown_state():
    # An unrecognized disposition must never silently hide a finding.
    assert fd.is_scoreable("garbage") is True


@pytest.mark.parametrize("target", ["false_positive", "risk_accepted"])
def test_note_required_for_risk_significant_targets(target):
    assert fd.note_required(target) is True


@pytest.mark.parametrize("target", ["open", "confirmed", "remediated"])
def test_note_not_required_for_other_targets(target):
    assert fd.note_required(target) is False


def test_can_transition_allows_any_distinct_pair():
    assert fd.can_transition("remediated", "open") is True
    assert fd.can_transition("open", "confirmed") is True


def test_can_transition_rejects_no_op():
    assert fd.can_transition("open", "open") is False


def test_can_transition_rejects_unknown_target():
    assert fd.can_transition("open", "nonsense") is False


def test_validate_transition_passes_for_simple_change():
    # No note needed moving to `confirmed`; must not raise.
    fd.validate_transition("open", "confirmed", None)


def test_validate_transition_rejects_unknown_target():
    with pytest.raises(fd.DispositionError):
        fd.validate_transition("open", "wontfix", None)


def test_validate_transition_rejects_no_op():
    with pytest.raises(fd.DispositionError):
        fd.validate_transition("confirmed", "confirmed", None)


@pytest.mark.parametrize("target", ["false_positive", "risk_accepted"])
def test_validate_transition_requires_note_for_risk_significant(target):
    with pytest.raises(fd.DispositionError):
        fd.validate_transition("open", target, None)
    with pytest.raises(fd.DispositionError):
        fd.validate_transition("open", target, "   ")  # blank == missing


@pytest.mark.parametrize("target", ["false_positive", "risk_accepted"])
def test_validate_transition_accepts_note_for_risk_significant(target):
    # A real note satisfies the requirement; must not raise.
    fd.validate_transition("open", target, "reviewed by appsec")


def test_validate_transition_ignores_note_when_not_required():
    # Providing a note for `remediated` is fine, just not mandatory.
    fd.validate_transition("open", "remediated", "fixed in PR 123")

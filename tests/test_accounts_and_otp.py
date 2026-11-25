"""Several identities, and a one-time code that never becomes evidence.

Authorisation findings need two accounts: the same URL as A and as B is two scopes, and the
second login must not inherit the first one's session. The OTP path is the operator, because
every other path is somebody's phone.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.pentest import accounts
from app.pentest.tools import mfa


def test_a_legacy_single_credential_still_works():
    account_set = accounts.normalise({"username": "alice", "password": "pw"})

    assert account_set.labels() == ["alice"]
    assert account_set.get("alice").password == "pw"


def test_several_accounts_keep_their_labels_roles_and_secrets():
    account_set = accounts.normalise(
        [
            {"label": "A", "role": "user", "username": "alice", "password": "pw1"},
            {"label": "B", "role": "admin", "username": "bob", "password": "pw2"},
        ]
    )

    assert account_set.labels() == ["A", "B"]
    assert account_set.get("B").role == "admin"
    # The prompt view never carries a password.
    assert "pw1" not in str([account.anonymous_view() for account in account_set.accounts])


def test_an_account_can_be_found_by_role():
    account_set = accounts.normalise(
        [
            {"label": "A", "role": "user", "username": "alice"},
            {"label": "B", "role": "admin", "username": "bob"},
        ]
    )

    assert account_set.get("admin").label == "B"


def test_auth_state_names_the_identity():
    account_set = accounts.normalise([{"label": "A", "username": "alice"}])

    assert account_set.auth_state() == "anonymous"
    account_set.active = "A"
    assert account_set.auth_state() == "authenticated:A"


def test_the_prompt_block_marks_who_is_logged_in_and_never_shows_a_password():
    account_set = accounts.normalise(
        [
            {"label": "A", "role": "user", "username": "alice", "password": "secret1"},
            {"label": "B", "role": "admin", "username": "bob", "password": "secret2"},
        ]
    )
    account_set.active = "B"

    rendered = account_set.render()

    assert "`A`: user, username alice" in rendered
    assert "currently logged in" in rendered
    assert "secret1" not in rendered and "secret2" not in rendered


def test_duplicate_labels_are_disambiguated():
    account_set = accounts.normalise(
        [{"label": "dup", "username": "a"}, {"label": "dup", "username": "b"}]
    )

    assert len(set(account_set.labels())) == 2


def test_accounts_are_bounded():
    raw = [{"label": f"a{index}", "username": f"u{index}"} for index in range(20)]

    assert len(accounts.normalise(raw).accounts) == accounts.MAX_ACCOUNTS


def test_a_code_is_extracted_from_whatever_the_operator_pastes():
    assert mfa.extract_code("482913") == "482913"
    assert mfa.extract_code("Your code is 482913, valid 5 minutes") == "482913"
    assert mfa.extract_code("G-482913") == "482913"
    assert mfa.extract_code("no code here") is None


def test_the_otp_tool_returns_the_code_and_masks_it_everywhere_else(monkeypatch):
    async def answers(*_args, **_kwargs):
        return "Your code is 482913", "answered"

    monkeypatch.setattr(mfa.questions_mod, "ask", answers)
    ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", emit=_noop)

    result = asyncio.run(mfa.request_otp(ctx, {"purpose": "login MFA", "channel": "sms"}))

    assert result.ok is True
    assert result.output["code"] == "482913"
    # The raw line the transcript stores carries no code.
    assert "482913" not in (result.raw or "")
    assert "do not write it" in result.output["note"]


def test_an_unanswered_request_fails_with_a_reason_the_agent_can_act_on(monkeypatch):
    async def no_answer(*_args, **_kwargs):
        return None, "no answer within 600s"

    monkeypatch.setattr(mfa.questions_mod, "ask", no_answer)
    ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", emit=_noop)

    result = asyncio.run(mfa.request_otp(ctx, {"purpose": "email MFA"}))

    assert result.ok is False
    assert "no code was provided" in result.error
    assert "record that the flow could not be completed" in result.error


def test_an_answer_without_digits_is_refused_rather_than_guessed(monkeypatch):
    async def vague(*_args, **_kwargs):
        return "check your phone", "answered"

    monkeypatch.setattr(mfa.questions_mod, "ask", vague)
    ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", emit=_noop)

    result = asyncio.run(mfa.request_otp(ctx, {"purpose": "sms MFA"}))

    assert result.ok is False
    assert "no recognisable code" in result.error


def test_the_stored_question_keeps_the_sentence_and_loses_the_code():
    """The operator's answer is evidence that a human supplied a code, not the code itself."""
    from app.pentest.questions import _DIGITS

    masked = _DIGITS.sub(lambda match: "…" + match.group(0)[-2:], "Your OTP is 482913, valid 5 min")

    assert masked == "Your OTP is …13, valid 5 min"
    assert "482913" not in masked


def test_the_otp_tool_is_marked_secret_so_stored_copies_are_masked():
    from app.pentest.tools import build_registry

    registry = build_registry()
    spec = registry.spec("request_otp")

    assert spec is not None
    assert spec.secret_output is True


async def _noop(*_args, **_kwargs):
    return None

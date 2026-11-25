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
    # The model reads the result's `raw`, so the code has to be there or it cannot use it.
    assert "482913" in (result.raw or "")
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


def test_an_account_carries_the_contacts_its_codes_go_to():
    account_set = accounts.normalise(
        [
            {
                "label": "A",
                "username": "alice",
                "role": "user",
                "phone": "+91 90000 04471",
                "email": "alice+scan@example.com",
            }
        ]
    )

    rendered = account_set.render()

    assert "phone +91 90000 04471" in rendered
    assert "email alice+scan@example.com" in rendered
    # And the instruction that stops an invented number.
    assert "Never invent one" in rendered


def test_the_otp_question_names_where_the_code_was_sent(monkeypatch):
    captured: dict[str, str] = {}

    async def record_question(*, run_id, question, context=None, mask_answer=False):
        captured["question"] = question
        return "123456", "answered"

    monkeypatch.setattr(mfa.questions_mod, "ask", record_question)
    ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", emit=_noop)

    asyncio.run(
        mfa.request_otp(
            ctx,
            {"purpose": "registration OTP for account B", "channel": "sms", "destination": "+91…4471"},
        )
    )

    assert "registration OTP for account B" in captured["question"]
    assert "sent by sms" in captured["question"]
    assert "to +91…4471" in captured["question"]


def test_ask_operator_returns_a_plain_answer_and_is_not_masked(monkeypatch):
    async def answers(*_args, **kwargs):
        assert kwargs.get("mask_answer") in (None, False)
        return "+91 90000 04471", "answered"

    monkeypatch.setattr(mfa.questions_mod, "ask", answers)
    ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", emit=_noop)

    result = asyncio.run(
        mfa.ask_operator(ctx, {"question": "Which mobile number should I register with?"})
    )

    assert result.ok is True
    assert result.output["answer"] == "+91 90000 04471"


def test_ask_operator_refuses_to_let_the_agent_proceed_on_a_guess(monkeypatch):
    async def no_answer(*_args, **_kwargs):
        return None, "no answer within 600s"

    monkeypatch.setattr(mfa.questions_mod, "ask", no_answer)
    ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", emit=_noop)

    result = asyncio.run(mfa.ask_operator(ctx, {"question": "Which tenant?"}))

    assert result.ok is False
    assert "Do not invent a value" in result.error


def test_both_operator_tools_are_in_the_catalogue():
    from app.pentest.tools import build_registry

    registry = build_registry()

    assert registry.spec("request_otp") is not None
    assert registry.spec("ask_operator") is not None
    # Only the code is a secret; a phone number the operator supplied is context.
    assert registry.spec("request_otp").secret_output is True
    assert registry.spec("ask_operator").secret_output is False


def test_the_model_reads_the_code_while_storage_keeps_the_mask():
    """The reported bug: the agent saw "…13" and could not complete the login.

    The prompt renders a tool result from `raw`, so the live entry must carry the code; the
    persisted entry must not.
    """
    from app.pentest.agent import _mask_secrets
    from app.pentest.tools.mfa import request_otp as _request_otp  # noqa: F401 — signature check

    import asyncio
    from types import SimpleNamespace

    from app.pentest import accounts as accounts_mod  # noqa: F401

    async def answers(*_args, **_kwargs):
        return "482913", "answered"

    import app.pentest.tools.mfa as mfa_mod

    original = mfa_mod.questions_mod.ask
    mfa_mod.questions_mod.ask = answers
    try:
        ctx = SimpleNamespace(run_id="00000000-0000-0000-0000-000000000001", emit=_noop)
        result = asyncio.run(mfa_mod.request_otp(ctx, {"purpose": "login"}))
    finally:
        mfa_mod.questions_mod.ask = original

    live_raw = result.raw or ""
    stored = _mask_secrets(result.output)

    assert "482913" in live_raw, "the model must be able to read the code"
    assert "482913" not in str(stored), "every stored copy keeps the mask"

"""Enterprise SSO surface (OIDC + SAML).

Module layout:

* ``encryption``    — Fernet helpers for ``sso_providers.config_encrypted``
                      (mirrors the LLM API key + SMTP password patterns).
* ``models``        — Pydantic models for the decrypted protocol configs
                      (``OidcConfig``, ``SamlConfig``); SSRF / scheme guards.
* ``repository``    — Async CRUD over ``sso_providers``; always returns the
                      decrypted config to in-process callers, never persists
                      plaintext.
* ``state_cookie``  — Signed, short-lived ``__Host-sso_state`` HttpOnly
                      cookie carrying ``provider_id``/``nonce``/``return_to``;
                      replaces the in-process LRU per threat-model M2.
* ``oidc``          — OIDC client factory + login + callback (id_token JWKS
                      verification per M1).
* ``saml``          — SAML SP wrapper around python3-saml (strict mode +
                      signed messages + signed assertions per M3).
* ``provisioning``  — JIT account creation / linking with policy checks
                      (M4 verified-email, M5 hard-coded ``is_superuser=False``).
* ``audit``         — Records ``auth_audit_events`` rows with correlation_id.
"""

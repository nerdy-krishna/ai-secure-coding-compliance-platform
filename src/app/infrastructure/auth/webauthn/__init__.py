"""WebAuthn / passkey authentication.

Module layout:

* ``challenge_cookie`` — short-lived signed `__Host-webauthn_challenge`
  cookie carrying the (provider-side-generated) challenge between
  begin / finish ceremonies. Replaces an in-process LRU; multi-worker
  compatible (mirrors the SSO state-cookie pattern).
* ``repository`` — Async CRUD on `webauthn_credentials`.
* (router lives at ``app.api.v1.routers.webauthn``)
"""

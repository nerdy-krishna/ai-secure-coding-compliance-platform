"""SCIM 2.0 server-side support (Users only — Groups deferred).

Module layout:

* ``schema``  — Pydantic models for SCIM User + ListResponse + Error.
* ``filter``  — minimal subset of SCIM filter syntax (`userName eq`,
                `emails.value eq`, `active eq`).
* ``auth``    — bearer-token dependency + CRUD on `scim_tokens`.
* (router lives at ``app.api.v1.routers.scim``)

Spec references: RFC 7642–7644.
"""

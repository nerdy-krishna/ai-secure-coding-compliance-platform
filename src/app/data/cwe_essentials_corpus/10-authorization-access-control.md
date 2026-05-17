---
concern_area: Authorization & Access Control
cwes: CWE-862, CWE-863, CWE-352, CWE-639, CWE-732, CWE-285
edition: CWE Top 25 (2025)
---

# Authorization & Access Control

Authorization weaknesses occur when an authenticated identity is
allowed to perform an action or reach data it should not. Authentication
establishes who the caller is; authorization decides what that caller
may do, and this concern-area is about failures of the second step. It
covers missing authorization (CWE-862), incorrect authorization
(CWE-863), cross-site request forgery (CWE-352), authorization bypass
through a user-controlled key (CWE-639), incorrect permission
assignment for a critical resource (CWE-732), and improper
authorization in general (CWE-285).

The root cause is most often a check that is absent, in the wrong
place, or trusting the wrong input. An object is fetched directly by an
identifier taken from the request, with no test that the caller owns
it — the insecure direct object reference pattern behind CWE-639.
Authorization is enforced only in the UI, or only on some of the
endpoints that expose an operation. A check uses a role or permission
value supplied by the client. CSRF is the related failure of not
confirming that a state-changing request was genuinely intended by the
user whose credentials it carries.

Mitigation is to perform an explicit authorization decision on the
server for every request that touches a protected resource, checking
the authenticated subject against the specific object and action.
Derive ownership and roles from server-side state, never from the
request body. Apply the checks through a single chokepoint so no
endpoint is missed, and default to deny. Protect state-changing
requests against CSRF with anti-forgery tokens or equivalent
same-site request validation. Grant the minimum permissions a resource
needs, and review permission assignments on files and objects so they
are not world-accessible.

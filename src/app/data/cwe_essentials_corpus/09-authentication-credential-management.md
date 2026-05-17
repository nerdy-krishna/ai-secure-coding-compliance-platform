---
concern_area: Authentication & Credential Management
cwes: CWE-287, CWE-306, CWE-798, CWE-259, CWE-522, CWE-521, CWE-384
edition: CWE Top 25 (2025)
---

# Authentication & Credential Management

These weaknesses occur when a system fails to reliably establish who is
making a request, or fails to protect the secrets that identity
depends on. This concern-area covers improper authentication
(CWE-287), missing authentication for a critical function (CWE-306),
use of hard-coded credentials (CWE-798), use of a hard-coded password
(CWE-259), insufficiently protected credentials (CWE-522), weak
password requirements (CWE-521), and session fixation (CWE-384).

The root causes split into two families. The first is gaps in
enforcement: a sensitive endpoint, administrative function, or
internal API is reachable without an authentication check, or the
check can be bypassed on an alternate path. The second is mishandled
credentials: passwords or API keys embedded in source or configuration,
secrets stored or transmitted without protection, password rules that
permit trivially guessable values, and session identifiers that are
not refreshed at login so a pre-authentication identifier survives into
the authenticated session.

Mitigation requires authenticating every entry point to a protected
resource, with the check enforced server-side and centrally so it
cannot be skipped. Keep secrets out of code and version control; load
them from a secrets manager or injected configuration, and rotate them.
Store passwords only as salted hashes from a slow, purpose-built
algorithm, never reversibly. Set credential strength by encouraging
length and screening against known-breached values rather than
imposing brittle composition rules. Issue a fresh session identifier
on every authentication and privilege change, bind sessions to a
reasonable lifetime, and prefer established identity frameworks over
bespoke authentication code.

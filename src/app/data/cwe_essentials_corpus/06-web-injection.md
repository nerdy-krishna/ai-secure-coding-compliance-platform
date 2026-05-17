---
concern_area: Web Injection
cwes: CWE-79, CWE-89, CWE-90, CWE-91, CWE-943
edition: CWE Top 25 (2025)
---

# Web Injection

Web injection weaknesses occur when untrusted input crosses into an
interpreted context — an HTML page, a SQL statement, an LDAP filter, an
XML document, or another query language — and is treated as structure
rather than as a value. This concern-area covers cross-site scripting
(CWE-79), SQL injection (CWE-89), LDAP injection (CWE-90), XML
injection (CWE-91), and the general improper neutralization of special
elements in data query logic (CWE-943), which spans NoSQL and other
query languages.

The root cause is the same across all of them: a string is assembled
by concatenating a fixed template with untrusted input, then handed to
an interpreter that cannot tell which characters came from the
developer and which from the attacker. In SQL and similar query
languages this lets input add clauses or terminate the statement; in
HTML it lets input introduce `<script>` or event handlers that run in
the victim's session.

Mitigation is to keep code and data separate by construction. For
databases, use parameterized queries or prepared statements so values
are bound, never concatenated; an ORM or query builder achieves the
same when used without raw string fragments. For LDAP, XML, and NoSQL,
use the binding or builder APIs the platform provides and escape
special elements with a context-aware encoder when binding is not
available. For XSS, apply output encoding appropriate to the exact
sink — HTML body, attribute, JavaScript, URL — at the point of output,
prefer frameworks that auto-escape, and add a Content Security Policy
as defence in depth. Input validation narrows the attack surface but
is not a substitute for context-correct encoding at the sink.

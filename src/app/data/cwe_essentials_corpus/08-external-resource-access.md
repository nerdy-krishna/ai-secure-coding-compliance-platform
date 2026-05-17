---
concern_area: External Resource Access
cwes: CWE-22, CWE-434, CWE-918, CWE-23, CWE-36, CWE-59, CWE-73
edition: CWE Top 25 (2025)
---

# External Resource Access

These weaknesses occur when untrusted input controls *which* external
resource a program reaches — a file, a directory, or a network
endpoint — rather than only the data exchanged with it. This
concern-area covers path traversal (CWE-22), unrestricted upload of a
file with a dangerous type (CWE-434), server-side request forgery
(CWE-918), relative and absolute path traversal (CWE-23, CWE-36),
improper link resolution before file access (CWE-59), and external
control of a file name or path (CWE-73).

The root cause is using attacker-influenced input to build a resource
identifier without confirming the identifier stays inside the intended
boundary. A filename containing `../` escapes the base directory; a
symlink redirects an access to a sensitive target; an uploaded file
with an executable extension lands in a served directory; a URL fetched
on the user's behalf points instead at an internal service or a cloud
metadata endpoint, turning the server into a proxy for the attacker.

Mitigation is to constrain the resource, not just sanitise the input.
For file paths, resolve the candidate to its canonical absolute form
and verify it is still within the permitted base directory before
opening it; prefer mapping user input through an indirection table to
known paths. For uploads, validate type by content rather than
extension, store files outside any served or executable location, and
assign server-generated names. For outbound requests, validate the
destination against an allowlist of permitted hosts, resolve and
re-check the address to defeat DNS rebinding, block private and
link-local ranges, and disable automatic redirects so a benign URL
cannot be bounced to an internal one.

---
concern_area: Sensitive Information Exposure
cwes: CWE-200, CWE-209, CWE-532, CWE-312, CWE-319, CWE-359
edition: CWE Top 25 (2025)
---

# Sensitive Information Exposure

These weaknesses occur when data that should stay confidential reaches
somewhere it can be observed by an actor who should not see it. The
exposed data is often valuable in itself — credentials, personal
information, keys — or it lowers the cost of a further attack by
revealing internal structure. This concern-area covers exposure of
sensitive information to an unauthorized actor (CWE-200), generation of
an error message containing sensitive information (CWE-209), insertion
of sensitive information into a log file (CWE-532), cleartext storage
of sensitive information (CWE-312), cleartext transmission of sensitive
information (CWE-319), and exposure of private personal information
(CWE-359).

The root cause is sensitive data leaving a controlled context through
a channel that was not considered. Error responses carry stack traces,
SQL fragments, or file paths to the client. Logs and telemetry record
request bodies, tokens, or personal data in the clear, then flow to
systems with broader access. Data is written to disk, caches, or
backups unencrypted, or sent over an unencrypted transport. A response
returns more fields than the caller is entitled to.

Mitigation is to classify sensitive data and control every channel it
can travel. Return generic error messages to clients and keep
diagnostic detail server-side. Redact or omit secrets and personal data
before logging, and treat logs as a protected store. Encrypt sensitive
data at rest and require authenticated, encrypted transport — TLS — for
it in transit. Shape responses to expose only the fields the caller is
authorized to see, rather than serialising an entire internal object.
Apply the same care to caches, backups, and temporary files, which are
easy to overlook.

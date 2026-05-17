---
concern_area: Improper Input Validation
cwes: CWE-20, CWE-129, CWE-1284, CWE-1287
edition: CWE Top 25 (2025)
---

# Improper Input Validation

Input-validation weaknesses occur when a program accepts data without
confirming that it has the properties the rest of the code assumes. The
data then violates an invariant somewhere downstream — an index goes
out of range, a quantity drives an oversized loop, a value of the wrong
type reaches code that cannot handle it. This concern-area covers
improper input validation in general (CWE-20), improper validation of
an array index (CWE-129), improper validation of a specified quantity
in input (CWE-1284), and improper validation of a specified type of
input (CWE-1287).

The root cause is an implicit trust boundary. Code at the edge of the
system — request handlers, file parsers, message consumers, IPC
endpoints — treats incoming data as already well-formed, so the checks
that should happen once at entry are scattered, partial, or absent.
Validation that exists is often incomplete: it checks format but not
range, or rejects known-bad values instead of requiring known-good
ones, leaving every unanticipated input to slip through.

Mitigation is to validate at the trust boundary, before the data is
used, against a positive specification. Define what each field must be
— its type, length, range, format, and permitted set — and reject
anything that does not match, rather than trying to enumerate bad
input. Validate array indices and quantities against the actual size
of the structure they will drive. Convert input to its intended type
explicitly and handle the failure case. Centralise validation so it
cannot be skipped on an alternate code path, and fail closed when a
value cannot be confirmed safe.

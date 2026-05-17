---
concern_area: Code Injection & Unsafe Deserialization
cwes: CWE-94, CWE-502, CWE-95, CWE-1336
edition: CWE Top 25 (2025)
---

# Code Injection & Unsafe Deserialization

These weaknesses occur when untrusted input is interpreted as code,
markup, or a serialized object graph instead of as inert data. The
result is that the attacker, not the developer, decides what logic the
program runs. This concern-area covers improper control of generation
of code (CWE-94), deserialization of untrusted data (CWE-502), eval
injection (CWE-95), and improper neutralization of special elements in
a template engine, also known as server-side template injection
(CWE-1336).

The root cause is feeding attacker-influenced data into a
language-level evaluation primitive. Dynamic-evaluation functions —
`eval`, `exec`, `Function`, runtime compilation — execute whatever they
are given. Native deserializers reconstruct arbitrary object types and
may invoke constructors, setters, or magic methods during the rebuild,
so a crafted payload can reach a gadget chain that runs code. Template
engines are an injection surface whenever user input is concatenated
into the template source rather than passed as a bound value.

Mitigation begins with never evaluating untrusted input as code. Remove
dynamic-evaluation calls where a data-driven design — a lookup table, a
dispatch map, a parser for a constrained grammar — will do. For
serialized data, prefer a pure data format such as JSON with a schema,
and deserialize into known, explicitly-typed structures; if a native
serializer must be used, restrict it to an allowlist of permitted
classes and apply integrity protection so payloads cannot be tampered
with. Pass user data to template engines only as context variables,
never as part of the template text, and keep template definitions out
of attacker control.

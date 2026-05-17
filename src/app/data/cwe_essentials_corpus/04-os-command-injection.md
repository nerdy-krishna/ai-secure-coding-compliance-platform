---
concern_area: OS & Command Injection
cwes: CWE-78, CWE-77, CWE-88
edition: CWE Top 25 (2025)
---

# OS & Command Injection

Command injection weaknesses occur when untrusted input reaches an
operating-system command interpreter or process launcher and is able
to change what gets executed rather than only what data is processed.
This concern-area covers improper neutralization of special elements
used in an OS command (CWE-78), the broader command injection class
(CWE-77), and argument injection or modification (CWE-88).

The root cause is building a command line by string concatenation and
handing it to a shell. The shell then interprets metacharacters —
semicolons, pipes, backticks, `$()`, ampersands, redirections — that
the attacker supplied, so a parameter that was meant to be a filename
becomes a second command. Argument injection is the subtler variant:
even with no shell involved, untrusted text inserted into an argument
list can introduce option flags that change a program's behaviour, for
example turning a search term into a flag that writes a file.

Mitigation starts with avoiding the shell entirely. Invoke programs
through array-based APIs that pass arguments as a vector, so the
operating system never re-parses them; never pass `shell=True` or its
equivalents with untrusted content. Where a value must be an argument,
validate it against a strict allowlist of expected forms and reject
anything else, and use `--` to terminate option parsing so input cannot
masquerade as a flag. Prefer a native library call over spawning a
process at all. If a shell is unavoidable, the only safe approach is a
rigorous allowlist of permitted values — escaping is error-prone and
should not be relied on.

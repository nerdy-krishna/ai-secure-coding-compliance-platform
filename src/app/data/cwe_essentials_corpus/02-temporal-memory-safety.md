---
concern_area: Temporal Memory Safety
cwes: CWE-416, CWE-476, CWE-415, CWE-401, CWE-824, CWE-825
edition: CWE Top 25 (2025)
---

# Temporal Memory Safety

Temporal memory weaknesses occur when code accesses memory at the
wrong point in its lifetime — before it is initialized, or after it
has been freed. Unlike spatial errors, the access can be perfectly
in-bounds; what is wrong is the timing. This concern-area covers
use-after-free (CWE-416), NULL pointer dereference (CWE-476), double
free (CWE-415), missing release of memory after its effective lifetime
(CWE-401), use of an uninitialized pointer (CWE-824), and dereference
of an expired or dangling pointer (CWE-825).

The root cause is unclear ownership: more than one piece of code
believes it is responsible for the lifetime of an allocation, or no
code is. A pointer is freed on one path and used on another; an object
is released while a reference, iterator, or callback still holds it; an
error path frees a resource the success path also frees; or a pointer
is declared but used before being assigned. Use-after-free is
particularly dangerous because the freed region is often reallocated
under attacker influence, turning a stale read or write into
controlled corruption.

Mitigation centres on giving every allocation a single, explicit
owner. Use RAII and smart pointers in C++ so release is tied to scope;
set pointers to NULL immediately after freeing and guard frees so they
run exactly once. Check every pointer that could be NULL — especially
allocation and lookup results — before dereferencing it. In Rust, lean
on the borrow checker and avoid `unsafe` aliasing; in garbage-collected
and Go code, watch for resources (files, handles, native buffers) that
escape their intended scope. AddressSanitizer and similar tools should
gate merges, since temporal bugs are otherwise easy to miss in review.

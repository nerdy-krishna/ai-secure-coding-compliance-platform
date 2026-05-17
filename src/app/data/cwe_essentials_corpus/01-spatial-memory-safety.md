---
concern_area: Spatial Memory Safety
cwes: CWE-787, CWE-125, CWE-119, CWE-122, CWE-121, CWE-786, CWE-788, CWE-805
edition: CWE Top 25 (2025)
---

# Spatial Memory Safety

Spatial memory weaknesses occur when code reads or writes a memory
location outside the bounds of the buffer it was meant to touch. They
are the dominant defect class in C and C++ and the leading cause of
remote code execution and information disclosure in native software.
This concern-area covers out-of-bounds writes (CWE-787), out-of-bounds
reads (CWE-125), the general failure to restrict operations within a
buffer's bounds (CWE-119), heap- and stack-based buffer overflows
(CWE-122, CWE-121), accesses before the start or after the end of a
buffer (CWE-786, CWE-788), and buffer access driven by an incorrect
length value (CWE-805).

The recurring root cause is an index, offset, or length that is
derived from untrusted input — or from an arithmetic result — without
being checked against the real size of the allocation. Copy loops that
trust a caller-supplied count, pointer arithmetic that walks past a
sentinel, and fixed-size stack buffers filled from variable-length
input are the classic shapes. Off-by-one errors at array boundaries
and confusion between element count and byte count are frequent
contributors.

Mitigation starts with never trusting a length: validate every index
and size against the destination capacity before the access, and treat
the smaller of source and destination size as the authoritative bound.
Prefer memory-safe constructs — bounded string and container types,
`std::span` or slice types, and standard-library algorithms — over raw
pointer arithmetic. In Rust and Go, keep array and slice indexing
inside checked APIs rather than reaching for `unsafe`. Enable
compiler and allocator hardening (bounds-checking sanitizers in
testing, stack canaries, fortified libc routines) so that residual
defects fail closed instead of corrupting adjacent memory.

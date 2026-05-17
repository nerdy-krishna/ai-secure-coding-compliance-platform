---
concern_area: Concurrency & Race Conditions
cwes: CWE-362, CWE-367, CWE-364, CWE-1265, CWE-366
edition: CWE Top 25 (2025)
---

# Concurrency & Race Conditions

Concurrency weaknesses occur when the correctness of code depends on
the timing or interleaving of operations that run concurrently, and an
unfavourable interleaving violates an invariant. They are hard to find
because the vulnerable window is narrow and the failure is
intermittent. This concern-area covers concurrent execution using a
shared resource with improper synchronization (CWE-362), the
time-of-check to time-of-use race (CWE-367), a signal-handler race
condition (CWE-364), unintended reentrant invocation of a non-reentrant
routine (CWE-1265), and a race condition within a thread (CWE-366).

The root cause is an operation that the developer assumed was atomic
but is not. State is read, a decision is made, and the state is acted
on — but between the check and the use, another thread, process, or
signal handler changes it. The TOCTOU pattern is the classic example:
a file's properties are validated and then the file is opened, and the
path is swapped in the gap. Reentrancy bugs arise when a signal handler
or callback re-enters code that was mid-update of shared state.

Mitigation is to make the check-and-act sequence indivisible. Protect
every access to shared mutable state with the same lock, hold it across
the whole critical section, and keep lock ordering consistent to avoid
deadlock. Prefer operating on a handle you already hold rather than
re-resolving a name — open the file once and act on the descriptor
instead of re-checking the path. Keep signal handlers minimal and
async-signal-safe, touching only atomic flags. Where possible, avoid
shared mutable state altogether through immutability, message passing,
or confining state to a single owner, which is the model Rust and Go
encourage.

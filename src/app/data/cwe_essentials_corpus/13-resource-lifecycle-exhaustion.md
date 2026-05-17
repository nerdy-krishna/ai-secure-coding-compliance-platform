---
concern_area: Resource Lifecycle & Exhaustion
cwes: CWE-400, CWE-770, CWE-404, CWE-772
edition: CWE Top 25 (2025)
---

# Resource Lifecycle & Exhaustion

These weaknesses occur when a program acquires a finite resource —
memory, file descriptors, threads, connections, disk space, CPU time —
without bounding how much it consumes or reliably releasing it when
done. The result is degradation or denial of service, often triggered
by ordinary load rather than a sophisticated exploit. This concern-area
covers uncontrolled resource consumption (CWE-400), allocation of
resources without limits or throttling (CWE-770), improper resource
shutdown or release (CWE-404), and missing release of a resource after
its effective lifetime (CWE-772).

The root causes are unbounded acquisition and unreliable release. On
the acquisition side, a request handler allocates work proportional to
attacker-supplied input — a declared length, a nesting depth, a result
-set size — with no ceiling, so a small request maps to a large cost.
On the release side, a resource opened on the success path is not
closed on an error path, or a long-lived loop leaks a handle each
iteration; the slow accumulation eventually exhausts the pool.

Mitigation is to bound every acquisition and guarantee every release.
Cap the size, count, depth, and rate of work a single request can
cause, and reject input that exceeds the limit before allocating. Apply
timeouts to operations that could otherwise run unbounded. Tie resource
release to scope so it runs on every path — `with`/`defer`/RAII or
`try`/`finally` — rather than relying on a manual close that an
exception can skip. Use connection and thread pools with hard ceilings
so that overload produces controlled rejection instead of collapse.

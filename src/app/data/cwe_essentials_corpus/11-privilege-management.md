---
concern_area: Privilege Management
cwes: CWE-269, CWE-250, CWE-271, CWE-272, CWE-1390
edition: CWE Top 25 (2025)
---

# Privilege Management

Privilege-management weaknesses occur when a process, component, or
user holds more capability than its task requires, or changes its
privilege level incorrectly. The danger is amplification: a defect in a
component that runs with high privilege becomes a far more serious
compromise than the same defect in a constrained one. This
concern-area covers improper privilege management (CWE-269), execution
with unnecessary privileges (CWE-250), privilege-dropping or lowering
errors (CWE-271), least-privilege violations (CWE-272), and weak
authentication that undermines a privilege boundary (CWE-1390).

The root cause is treating privilege as a convenience rather than a
budget. A service runs as root or administrator because it once needed
a privileged operation at startup and never relinquished the rights. A
program intends to drop to an unprivileged identity but does so in the
wrong order, ignores the failure of the drop, or leaves a supplementary
group or capability behind. A trust boundary between privilege levels
is guarded by an authentication step that is weak enough to cross.

Mitigation is to grant the least privilege that works and to hold it
for the shortest time. Run each component under a dedicated,
unprivileged account; acquire an elevated capability only for the
specific operation that needs it and release it immediately. When
dropping privileges, perform the steps in the correct order, drop
supplementary groups and capabilities as well as the primary identity,
and verify the new state — treating any failure as fatal. Separate
privileged operations into a small, well-reviewed component behind a
narrow interface, and protect every privilege boundary with strong
authentication.

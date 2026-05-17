---
concern_area: Numeric, Type & Conversion Errors
cwes: CWE-190, CWE-191, CWE-369, CWE-681, CWE-194, CWE-195, CWE-704, CWE-843
edition: CWE Top 25 (2025)
---

# Numeric, Type & Conversion Errors

Numeric and type weaknesses occur when a value behaves differently
from what the developer assumed because of the limits of its
representation. They rarely cause harm on their own, but they routinely
feed a more serious defect — an undersized allocation, a bypassed
bounds check, or a corrupted decision. This concern-area covers integer
overflow and wraparound (CWE-190), integer underflow (CWE-191), divide
by zero (CWE-369), incorrect conversion between numeric types (CWE-681),
unexpected sign extension (CWE-194), signed-to-unsigned conversion
errors (CWE-195), incorrect type conversion or cast (CWE-704), and type
confusion (CWE-843).

The recurring root cause is arithmetic or conversion performed without
regard for range and signedness. A size computed by multiplying two
attacker-influenced values wraps to a small number, so the subsequent
allocation is too small. A length stored as a signed integer goes
negative and defeats a `length < limit` check. A wide value is
truncated when narrowed, or a negative value becomes huge when
reinterpreted as unsigned. Type confusion arises when memory is
interpreted as the wrong object type, often after an unchecked cast or
a tagged-union mismatch.

Mitigation begins with validating numeric inputs against an explicit
range before they are used in arithmetic, indexing, or allocation.
Perform size calculations in a width that cannot overflow, or use
checked-arithmetic helpers that signal overflow instead of wrapping.
Be deliberate about signedness — prefer unsigned types for sizes and
counts, and avoid mixing signed and unsigned operands. Guard divisors
against zero. Treat every cast as a place where an assumption is being
made, and verify the runtime type before down-casting.

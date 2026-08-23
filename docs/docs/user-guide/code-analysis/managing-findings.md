---
sidebar_position: 3
title: Managing Findings
---

# Managing Findings

Once a scan reaches `COMPLETED`, the Results page surfaces the final
consolidated findings. Operators can triage findings individually or in
bulk; remediation itself is selected when the scan is submitted.

## Suggested fixes

A `SUGGEST` (or `REMEDIATE`) scan produces an AI-suggested fix for
each finding the agent could remediate. On the finding detail panel
the fix renders as an inline before/after diff; **Expand** opens it
full-screen. A `SUGGEST` scan is **advisory** — it shows the fix so
you can review and apply it yourself; it does not mutate your code.

The header's **Patch plan** download contains the immutable JSON plan:
source hashes, exact resolved ranges, unified diffs, stable hunk IDs,
candidate-to-hunk lineage, requirements, and every rejected/manual-review
decision. It is available for both SUGGEST and REMEDIATE.

## Getting fixes applied

SCCAP applies fixes only on a **`REMEDIATE`** scan. The worker resolves each
candidate against the exact original source hash and byte range. Ambiguous
anchors and transitively overlapping edits are retained for manual review;
disjoint edits apply atomically in descending byte order. A whole-file
tree-sitter failure rolls back that file. Accepted files become a patched
`POST_REMEDIATION` code snapshot. To have a codebase patched, submit it (or
re-submit it) with `scan_type=REMEDIATE`.

The patch plan distinguishes a failed parser from a missing tool, skipped or
not-run validation, timeout, and infrastructure error. None of those states is
displayed as a successful check. Semgrep verification follows the exact native
rule at the resolved patch site rather than treating any same-CWE finding in
the file as the original issue.

## Downloading the patched tree

When the remediation run completes, the header gains a
**Download patched codebase** button. It zips the
`POST_REMEDIATION` code snapshot and streams it to the browser.
Diff the zip contents against your working copy to review what
changed.

## Triaging findings

Every finding starts as **Open**. From the Results page, a user who can
view the scan can move it to:

- **Confirmed** — a reviewed vulnerability that still contributes to risk.
- **False positive** — excluded from risk; a justification is required.
- **Remediated** — excluded from risk after the fix is dealt with.
- **Risk accepted** — excluded from risk; a justification is required.

The same action can be applied to a selected group of findings. Every
change records the actor, timestamp, previous state, new state, and note
in an append-only disposition history. Re-triage is allowed, including
moving a regressed fix back to Open.

Superusers can delete a disposition, which resets the finding to Open
and permanently removes that finding's disposition history. This is
different from an ordinary re-triage transition and should be used
sparingly.

Risk totals and dashboards count Open and Confirmed findings. False
Positive, Remediated, and Risk Accepted findings remain visible in the
results and exported reports but do not contribute to risk calculations.

## Re-scanning after a fix

Once a `REMEDIATE` scan has produced a patched tree and you've
integrated it into your own repo, submit a fresh scan under the same
project name.
The Projects grid shows the new posture side-by-side with the
previous run; the trend delta is visible on the card.

## Admin visibility

Visibility follows the scan's user/group scope. A user who can view the
scan can triage it; only a superuser can delete disposition history.

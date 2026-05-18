---
sidebar_position: 3
title: Managing Findings
---

# Managing Findings

Once a scan reaches `COMPLETED`, the Results page surfaces findings
that are candidates for remediation. SCCAP supports selective,
incremental fix application — you control which findings are
applied, and a merge agent resolves conflicts between overlapping
fixes.

## Suggested fixes

A `SUGGEST` (or `REMEDIATE`) scan produces an AI-suggested fix for
each finding the agent could remediate. On the finding detail panel
the fix renders as an inline before/after diff; **Expand** opens it
full-screen. A `SUGGEST` scan is **advisory** — it shows the fix so
you can review and apply it yourself; it does not mutate your code.

## Getting fixes applied

SCCAP applies fixes only on a **`REMEDIATE`** scan. There, the worker
graph merges the per-finding fixes, syntax-verifies them with
tree-sitter, and writes a patched `POST_REMEDIATION` code snapshot —
the single verified remediation path. To have a codebase patched,
submit it (or re-submit it) with `scan_type=REMEDIATE`.

## Downloading the patched tree

When the remediation run completes, the header gains a
**Download patched codebase** button. It zips the
`POST_REMEDIATION` code snapshot and streams it to the browser.
Diff the zip contents against your working copy to review what
changed.

## Dismissing / suppressing findings

SCCAP treats every finding as "open" unless a remediation applied
the associated fix. There is no dedicated "dismiss" state in this
release — false positives stay in the result. Two workarounds:

- Re-run the scan against a narrower file set to exclude the
  problematic area.
- Rely on the finding's confidence score during triage.

Formal finding lifecycle (acknowledged / dismissed / suppressed) is
on the [roadmap](../../roadmap.md).

## Re-scanning after a fix

Once a `REMEDIATE` scan has produced a patched tree and you've
integrated it into your own repo, submit a fresh scan under the same
project name.
The Projects grid shows the new posture side-by-side with the
previous run; the trend delta is visible on the card.

## Admin visibility

When scoped visibility is set up (H.2 user groups), any admin or
group peer can see the findings and remediation results of a scan
they can see.

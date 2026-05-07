---
sidebar_position: 5
title: Unit Test Integration
---

# Unit Test Integration

!!! info "Roadmap item"

    **This feature is not yet available.** It's on the
    [roadmap](../roadmap.md) as "Test-Validated Remediation" — the goal
    is to run the project's existing test suite against an AI-generated
    fix before SCCAP applies it, rejecting fixes that break tests.

## What's planned

When remediation is requested, SCCAP will:

1. Detect the project's test runner (`pytest`, `jest`, `go test`,
   `cargo test`, etc.) by scanning standard config files.
2. Apply each selected fix to a working copy.
3. Run the project's existing tests inside an ephemeral container.
4. Keep the fix if tests pass; roll back and surface the failure if
   they don't.
5. Record the per-fix pass/fail outcome alongside the
   `POST_REMEDIATION` snapshot so users can see which suggestions
   survived validation.

## Until then

The current remediation pipeline (see
[Managing Findings](./code-analysis/managing-findings.md)):

- Applies fixes incrementally with a merge agent for overlapping
  edits.
- Writes a `POST_REMEDIATION` snapshot for diffing.
- **Does not** run your tests. Run them yourself on the downloaded
  patched codebase before merging.

If you have strong opinions about the test-runner detection model
we should pick (greedy auto-detect vs. explicit config vs. declared
via `Admin → System config`), please open a discussion on the
repository — real-world preferences will drive the design.

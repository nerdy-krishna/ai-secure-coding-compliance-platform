# ADR-032: Plan-first assessment loop with stored evidence

## Status

Accepted

## Context

The agent discovered surface and then chose a tool each turn. Two consequences were
visible in real runs: the same endpoint was probed repeatedly in fractionally
different ways (`sqlmap --level=1`, then `--level=3`), and the run could not say what
it had *intended* to test, so "exhausted" was unmeasurable. Tool output was stored
truncated (4 k chars in the transcript, 220 in a digest), so examining a result meant
re-running the tool — the most expensive way to read.

## Decision

- **Recon first, in full.** Every discovery tool runs before the model sees anything,
  and every payload is stored whole (`pentest_run_artifacts`). The model can read any
  stored output on demand instead of re-running the tool.
- **A plan before any testing.** One model call turns recon into hypotheses: endpoint,
  vulnerability class, and the evidence that justifies it. The plan is stored
  (`pentest_hypotheses`) and shown in every later prompt.
- **Hypotheses close with a verdict.** confirmed, ruled_out (with the evidence) or
  blocked (with the reason). Running a tool is not a verdict, and `done` is deferred
  while hypotheses remain open.
- **Reads replace re-runs.** A turn may return artefact ids in `read`; that turn runs
  no tools and the payload appears in the next prompt.
- **The holistic review is part of the run.** A finished assessment with findings
  queues the chain pass automatically (`PENTEST_AUTO_CHAIN`), so chaining is not a
  button someone has to remember.

## Consequences

- Duplication has a defined floor: an intent is worked once, and evidence is re-read
  rather than re-collected.
- Run cost per hypothesis is measurable (attempts, verdicts), which is what makes
  "exhausted" a claim rather than a feeling.
- Prompt size grows with the plan and the artefact index, both bounded; the raw
  payloads stay in the database until asked for.
- A plan can be wrong. The loop may add leads and hypotheses mid-run; a plan that
  misses something does not block discovery, it only fails to prioritise it.

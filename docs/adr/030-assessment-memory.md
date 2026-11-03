# ADR-030: Assessment memory — a durable transcript with compaction

## Status

Accepted

## Context

The autonomous assessment agent rebuilds its prompt from the database on every
turn. That is what makes operator steering immediate and restarts cheap: nothing
lives only in a process.

It also meant the agent had almost no memory. `history` was an in-process list, so
an engine restart resumed with recon and the lead queue but no recollection of why
it had made its choices. Only tool *results* were recorded, never the turn's own
calls and arguments — the model could see that `nuclei` had run, not on what, which
is why duplicate probes were proposed and then discarded by the dedupe guard. And
anything older than 30 entries was dropped, so early findings and dead ends were
silently re-explored.

The obvious fix — keep the whole conversation — is wrong. A 200-turn run with full
tool output is roughly 800 KB of prompt: expensive, slow, and past the context
window of most models. The information that matters is a small fraction of it.

## Decision

Store the transcript durably and compact it, rather than truncating or unbounded
growth:

- **Persist every turn** (`pentest_run_transcript`): the agent's reasoning and
  calls (with arguments), tool results **in full**, nudges and errors. Truncation
  happens only when an entry is rendered into a prompt.
- **Resume from it.** A restart loads the live transcript, so the loop continues
  with the same memory; the durable probe log already covered "do not repeat this".
- **Compact past a budget** (`PENTEST_TRANSCRIPT_COMPACT_TOKENS`, default 120k
  tokens): older entries are condensed by the model into
  `pentest_runs.transcript_summary`, and the rows they covered are marked
  `compacted_at`. Marked rows are **kept for audit** and stop being prompted.
- **Keep the tail verbatim** (`PENTEST_TRANSCRIPT_KEEP_TURNS`, default 10), because
  the next decision depends on the immediate context.
- **Compaction can fail without failing the run.** If the summary call fails, the
  loop carries on with the uncompacted transcript and retries later.
- **Order in the prompt**: brief → directives → recon → lead queue → *compacted
  summary* → history. The summary is labelled as the agent's own record so it does
  not read it as somebody else's notes.

For the chain agent, the same principle applies to findings: it receives an
**index** (id, score, CWE, proof status, title) and asks for the detail it needs
with `read`. Prompt size is then bounded by curiosity, not by how much a tool
found, and a run with hundreds of observation cannot hide surface behind a
truncation limit.

## Consequences

- Restarts and long runs keep their memory; the audit trail is complete because
  compaction retires rows rather than deleting them.
- Prompt cost grows with the *decision-relevant* history, not with raw tool output.
- Compaction is an extra model call on a large run; it is bounded (one per overflow
  event) and failures are non-fatal.
- The summary is a model-generated artefact stored against the run. It is labelled
  as such in the prompt and in the transcript, so it is never mistaken for evidence.
- The chain agent's `read` step spends a turn without running tools. That is
  deliberate: it looks before it leaps, and the alternative — inlining everything —
  is what hid the evidence in the first place.

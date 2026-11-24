# ADR-033: Borrowed methodology, and the provenance of every claim

**Status:** accepted · **Date:** 2026-11-24

## Context

Two outside projects describe a more mature autonomous-assessment loop than ours:
**ARTEX** (AGPL-3.0, Go, upstream deleted) and **Norma** (Apache-2.0), the agent-harness SDK
ARTEX is built on. Their design deserves to be taken seriously: two linked graphs, role-separated
agents, a coverage ledger, an adversarial gate before reporting, evidence bound to captured
traffic, and lessons extracted from closed tasks.

We want that behaviour. We do not want their licence, and we do not want their prose.

## Decision

### 1. Behaviour is source material; expression is not

- **ARTEX (AGPL-3.0): read only.** No code, no prompt text, no test fixtures, no docs prose is
  copied into this repository. AGPL and Apache-2.0 do not combine in the direction we need, and
  §13 would extend the obligation to every user of the deployed service.
- **Norma (Apache-2.0): portable.** Its designs may be translated into Python, including close
  translation of implementation, with attribution in `NOTICE` and in the table below.
- **Their Go tests are the specification.** Tests state behaviour; behaviour is not
  copyrightable. We read them, write a behaviour spec, and implement against the spec.

### 2. Clean-room discipline for prompts

Every role prompt is authored from a **behaviour spec**: inputs, tool contract, required
outputs, forbidden behaviours, and the acceptance test that fails when the prompt is wrong.
The spec is written first, the prompt second. No ARTEX prompt text is paraphrased — a
paraphrase is a derivative work, and a spec is not.

### 3. Every claim carries a provenance

A finding may not rest on the agent's reasoning. Facts are first-class rows with a source
class, and only two classes can prove anything:

| Source | Meaning | Can prove a finding |
|---|---|---|
| `target_response` | the target itself returned it (body, header, banner, error, even via a tool) | yes |
| `tool_output` | a tool's own result about the target | yes |
| `third_party_intel` | OSINT, CVE feeds, public reports | no |
| `operator_input` | supplied by the human operator | no |
| `inference` | the agent's reasoning | no |

"A version matches a CVE" is `third_party_intel` plus `inference`; it can never be a finding on
its own. This is the same rule we already apply to CVE verdicts, generalised to the whole engine.

### 4. Provenance of our own borrowing

| Borrowed behaviour | Source | How it enters this repo |
|---|---|---|
| Fact provenance classes; "target_response never proves a goal alone" | ARTEX docs/prompts (behaviour) | reimplemented from spec — `pentest/facts.py` |
| Two-graph state: asset graph + exploration graph, intents as auditable nodes | ARTEX architecture docs | reimplemented — `pentest_plan` graph (P2) |
| Coverage ledger: five outcomes, "unexamined is never clean", gap kinds | ARTEX `db/coverage_ledger.go` (behaviour) | reimplemented — P2 |
| Adversarial gate on five axes; measured impact; dedupe by root cause | ARTEX prompts (behaviour) | reimplemented — P3 |
| Evidence bound to captured traffic | ARTEX `docs/vulnerability-traffic-evidence.md` | reimplemented over a mitmproxy sidecar — P6 |
| Nonce-framed untrusted tool output | ARTEX ADR-001 (idea) | reimplemented — `pentest/untrusted.py` |
| Deferred tool schemas, on-demand discovery | Norma (Apache-2.0) | pending (P8) |
| Dial-time DNS pinning, redirect re-check | ARTEX ADR-002 (idea) | reimplemented in `pentest/ssrf.py` |
| Per-host egress governor (bucket, jitter, backoff) | ARTEX `egress/` (behaviour) | reimplemented — `pentest/egress.py` |
| Shell allowlist grammar (no wrapper/pipeline inheritance) | ARTEX `intercept` (behaviour) | reimplemented — `tools/harness.py` |
| Deadline contract, wrap-up priority, stagnation detection | ARTEX prompts (behaviour) | reimplemented — `pentest/doctrine.py`, `pentest/stagnation.py` |
| Findings bound to captured traffic; HAR export | ARTEX `docs/vulnerability-traffic-evidence.md` (behaviour) | reimplemented — `pentest/traffic.py`, `deploy/pentest-proxy/` |
| Permission pipeline: allow/deny/ask, deny-priority, four stages | **Norma (Apache-2.0)** | translated to Python — P5 |
| Lifecycle hooks (PreToolUse/PostToolUse/Stop) | **Norma (Apache-2.0)** | translated to Python — P5 |
| Compaction: snip / micro / collapse / auto, circuit breaker, reactive recovery | **Norma (Apache-2.0)** | adapted into `pentest/memory.py` — P4 |
| Deferred tool schemas, on-demand discovery | **Norma (Apache-2.0)** | reimplemented over our registry — P8 |
| Skills as `SKILL.md` packages injected on demand | **Norma (Apache-2.0)** | reimplemented — P8 |
| Evidence-gated lessons, withdrawn on disposition reversal | ARTEX `docs/rsi-lessons.md` (behaviour) | reimplemented — P7 |
| Role separation: goals / planner / worker / re-tester, cheap model for planning | ARTEX architecture docs (behaviour) | reimplemented — `pentest/roles.py`, `pentest/goals.py` |
| Adversarial gate on five axes, machine-answered where the machine knows | ARTEX prompts (behaviour) | reimplemented — `pentest/gate.py` |
| Re-test by replaying the captured request; the responses decide | ARTEX `retester` (behaviour) | reimplemented — `pentest/retester.py` |

### 5. What we deliberately keep from our own engine

The scope ledger with `rerun_reason` (a better answer to "never re-scan a covered scope" than
anything in either project), the harness/diagnose allowlist, the three approval gates, severity
normalisation with the unknown-CWE ceiling, and plan-first assessment (ADR-032). Borrowing must
not regress these.

## Roles

The loop is split by job, not by process:

| Role | Does | Model |
|---|---|---|
| `goals` | deliverables and constraints, before any plan | cheapest priced config |
| `planner` | hypotheses and first actions, from recon + goals | cheapest priced config |
| `worker` | executes, records facts, records coverage | the run's model |
| `judge` | argues against each finding on three axes | cheapest priced config |
| `retester` | replays the captured request and compares | no model at all |

The cheap model is chosen deterministically: an operator pin (`PENTEST_*_LLM_CONFIG_ID`), else
the lowest resolved input price among configured models, else the run's model. A model with no
known price is never assumed cheap. Every choice is emitted on the run's event stream, so spend
per role is attributable rather than one anonymous number.

The judge is capped at 12 findings per run, because a scanner can report dozens and arguing each
one costs more than the assessment.

## Consequences

- Implementation is slower than copying, by a few days per phase, and every borrowed behaviour
  arrives with a spec we can test.
- A future contributor may not paste AGPL text or code. If a prompt or module was derived from
  ARTEX, it was derived from its *behaviour*, and this table records it.
- Third-party prompt text is never executed in our agent: the surviving ARTEX copies are forks
  of a deleted upstream, and one fork documents use of the tool in a real criminal intrusion.
  Prompt text is instruction, not documentation; importing it would run someone else's
  instructions against our customers' scope.

## References

- ARTEX architecture: `docs/ARCHITECTURE.md` (two graphs, roles, trust boundaries).
- Norma: agent-harness SDK, Apache-2.0, `permission`, `hook`, `compaction`, `skill`, `tool`.
- ADR-032 (plan-first loop), ADR-031 (CVE applicability), ADR-029 (pentesting engine).

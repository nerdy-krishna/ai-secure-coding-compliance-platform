# ASVS Enriched Corpus — Authoring Spec (LOCKED)

This is the locked format + quality bar for the ASVS RAG enrichment effort.
Every chapter YAML under `src/app/data/asvs_corpus/` is authored against
this spec. The exemplar is `V1-encoding-and-sanitization.yaml` — read it
in full before authoring any other chapter; match its depth and style.

## What you are producing

One YAML file per ASVS chapter: `src/app/data/asvs_corpus/V<N>-<slug>.yaml`
(slug = lowercased chapter name, words joined by `-`). The file is a YAML
list of entries — **one entry per ASVS requirement** in that chapter.

`scripts/build_enriched_corpus.py` renders these YAMLs into
`asvs_corpus.csv` (the ingestable RAG corpus). Do **not** edit the CSV;
do **not** run `--write` (the orchestrator does the final render).

## Entry schema

```yaml
- id: V<chapter>.<section>.<req>      # exact ASVS req_id, e.g. V6.2.3
  facet: <chapter_name>               # the chapter name verbatim, e.g. Authentication
  section: <section_name>             # the ASVS section_name (metadata, for review)
  level: <1|2|3>                      # the ASVS L column (metadata)
  security_rule: >-                   # the requirement restated as a clear principle
    ...
  vulnerability_pattern: >-            # CONCEPT description of the insecure pattern
    ...
  secure_pattern: >-                   # CONCEPT description of the secure pattern
    ...
  code_patterns:                       # short seed-sized snippets, per language
    generic:    {vulnerable: ..., secure: ...}
    python:     {vulnerable: ..., secure: ...}
    javascript: {vulnerable: ..., secure: ...}
    java:       {vulnerable: ..., secure: ...}
    csharp:     {vulnerable: ..., secure: ...}
```

## Field rules

- **`id`** — the exact `req_id` from `src/app/data/asvs_5.0.0_source.csv`.
  Author every requirement whose `chapter_id` matches your chapter. No
  skips, no merges, no invented ids.
- **`security_rule`** — restate the ASVS `req_description` as a crisp,
  imperative principle. Paraphrase; do not just copy. One or two sentences.
- **`vulnerability_pattern`** / **`secure_pattern`** — one to two sentences
  each, describing the *concept* (not code). These feed the scan agent's
  generic fallback when no language block matches.
  - HARD CONSTRAINT: these two fields must contain **no `*` and no `[`
    character** — the agent's extractor regex (`[^*\[]`) truncates on
    them. The build script rejects violations. Rephrase to avoid them
    (e.g. write "for example" instead of using brackets).
- **`code_patterns`** — short, seed-sized snippets. A single line is fine
  and often best — the goal is to *seed* the LLM, not ship a demo. Each
  language gets a `vulnerable` and a `secure` snippet that are a minimal
  contrasting pair. Use YAML block scalars (`|`) for code.
- **Languages**: `generic` (language-agnostic pseudocode) plus the four
  ASVS-relevant languages: `python`, `javascript`, `java`, `csharp`.
  - **Fill only applicable languages.** Always include `generic`. Include
    a real language only when the requirement is meaningfully expressible
    as code in it. A pure configuration/architecture/process requirement
    (no code sink) may be `generic`-only. Do not pad with contrived code.
  - When a requirement is about a server-side concern that all four
    languages share (headers, cookies, query APIs, crypto calls), fill
    all five. When it is browser-only, `generic` + `javascript` may
    suffice. Use judgement; quality over coverage.

## Quality bar (match the V1 exemplar)

- The vulnerable snippet shows the *realistic* mistake; the secure snippet
  is the minimal correct fix using the idiomatic safe API for that
  language. They must be a true before/after pair.
- Prefer correctness over cleverness. Code must be plausible and accurate
  for the language — a reviewer who knows the language should nod.
- Keep snippets short. One to four lines each. Single-line is encouraged.
- No placeholder text, no TODOs, no "see above". Every entry stands alone.

## Verification (orchestrator runs this; you do not)

After all chapters are authored:
`python scripts/build_enriched_corpus.py --framework asvs --check/--write`
then `_extract_patterns_from_doc` is asserted to return non-empty
vulnerable + secure patterns for every entry in all five languages.

"""Canonical agent prompt templates.

The text files in this package are the source of truth for the prompt
strings the worker runs. `default_seed_service.py` loads them at module
load via `importlib.resources` so the seed code stays small and the
prompts can be diffed in isolation.

`audit.md` / `remediation.md` are the generic templates (used by ASVS
and the AI frameworks). `chat.md` is the Advisor prompt. The
`audit_<framework>.md` / `remediation_<framework>.md` files are the
per-framework variants (Framework Expansion #57) — Proactive Controls
and Cheatsheets each get their own scan/remediation prompt, selected in
`_build_prompt_templates` by the agent's framework.

The eval extractor at `scripts/extract_eval_prompts.py` re-imports the
loaded constants (`_AUDIT_TEMPLATE`, `_REMEDIATION_TEMPLATE`,
`_CHAT_TEMPLATE`) from `default_seed_service`; those names stay bound to
the generic templates so the eval suite is unaffected.
"""

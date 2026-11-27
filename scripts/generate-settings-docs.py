#!/usr/bin/env python3
"""Render the admin-settings reference from the backend catalog.

The catalog (`app/shared/lib/settings_catalog.py`) is what the admin UI renders and
what the write path validates against. Generating this page from it means the docs
cannot describe a limit that the platform no longer has, or miss one it gained.

    python3 scripts/generate-settings-docs.py            # writes the page
    python3 scripts/generate-settings-docs.py --check     # exits 1 when stale (CI)

Run it after changing the catalog or the defaults in `config.py`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

TARGET = REPO_ROOT / "docs" / "docs" / "operations" / "admin-settings-reference.md"

APPLIES = {
    "live": "within 30 s",
    "next-scan": "next scan",
    "worker-restart": "worker restart",
    "app-restart": "API restart",
}

# Fields that are edited on their own admin card (not in the catalog) because they are
# not a single number or boolean. Documented here so the page is complete.
OTHER_FIELDS = [
    (
        "Application log level",
        '`system.log_level` — `{"level": "INFO"}`',
        "DEBUG / INFO / WARNING / ERROR / CRITICAL",
        "Minimum level written to the process log. Warnings and errors are always kept.",
        "immediately",
    ),
    (
        "LLM optimisation mode",
        '`llm.optimization_mode` — `{"mode": …}`',
        "`multi_provider`, `anthropic_optimized`",
        "Prompt-cache strategy. Anthropic-optimised reorders the prompt for cache hits; changing it invalidates caches on the next scan.",
        "next scan",
    ),
    (
        "Allowed CORS origins",
        "`security.allowed_origins`",
        "One origin per entry, scheme + host (+ port)",
        "Extra origins allowed to call the API from a browser. The UI origin is always allowed.",
        "immediately",
    ),
    (
        "Session lifetime",
        '`security.session_lifetime_hours` — `{"hours": 24}`',
        "1 … 168 hours",
        "Absolute session lifetime enforced at login.",
        "immediately",
    ),
    (
        "Retention windows",
        "`system.retention.llm_interaction_days`, `…chat_message_days`, `…rag_job_days`",
        "1 … 3650 days",
        "How long LLM interaction, chat and RAG rows are kept before the retention sweep.",
        "immediately",
    ),
    (
        "Feature flags",
        "`features.<name>`",
        "true / false",
        "Enable or disable a gated capability (scan, pentest, chat, sso, scim, …).",
        "immediately",
    ),
    (
        "Setup wizard state",
        "`setup.*`",
        "managed by the wizard",
        "Whether first-run configuration is complete. Changing it re-opens the wizard.",
        "immediately",
    ),
]


def render() -> str:
    from app.shared.lib.settings_catalog import DESCRIPTORS, SECTIONS

    lines: list[str] = [
        "# Admin settings reference",
        "",
        "Every value that can be changed from **Admin → System Config**, what it does, the",
        "values it accepts, and when a change takes effect.",
        "",
        "Resolution order is **database row → `.env` → the field default**, and every value is",
        "clamped to the range below. A fresh install seeds each setting at its maximum so",
        "nothing is throttled out of the box; lower them for the provider plan you actually",
        "pay for. Secrets and deployment coordinates (database/broker hosts, credentials,",
        "S3/KMS keys) are deliberately **not** here: they belong in `.env` on the host.",
        "",
        "> This page is generated from `app/shared/lib/settings_catalog.py` — the same table",
        "> the admin UI renders and the write path validates against. Run",
        "> `python3 scripts/generate-settings-docs.py` after changing it.",
        "",
    ]

    descriptions = dict(SECTIONS)
    for name, description in SECTIONS:
        entries = [d for d in DESCRIPTORS if d.section == name]
        if not entries:
            continue
        lines += [
            f"## {name}",
            "",
            description,
            "",
            "| Setting | Key | Values | Effect | Takes effect |",
            "|---|---|---|---|---|",
        ]
        for entry in sorted(entries, key=lambda d: d.label):
            if entry.kind == "int":
                low = "—" if entry.minimum is None else int(entry.minimum)
                high = "—" if entry.maximum is None else int(entry.maximum)
                values = f"{low} … {high}" + (f" {entry.unit}" if entry.unit else "")
            elif entry.kind == "bool":
                values = "true / false"
            else:
                values = ", ".join(f"`{choice}`" for choice in entry.choices)
            lines.append(
                f"| {entry.label} | `{entry.key}` | {values} | {entry.description} "
                f"| {APPLIES.get(entry.applies, entry.applies)} |"
            )
        lines.append("")

    lines += [
        "## Editor-only fields",
        "",
        "These are edited on their own card rather than as a number in a section, and are",
        "listed here so nothing the admin UI can change is undocumented.",
        "",
        "| Setting | Key | Values | Effect | Takes effect |",
        "|---|---|---|---|---|",
    ]
    for label, key, values, effect, applies in OTHER_FIELDS:
        lines.append(f"| {label} | {key} | {values} | {effect} | {applies} |")
    lines += [
        "",
        "## Not configurable, by design",
        "",
        "- **Credentials** — `SECRET_KEY`, `ENCRYPTION_KEY`, provider API keys, SMTP and",
        "  S3/KMS secrets, VAPID keys. A web session must never be able to read or rotate a",
        "  secret that is only stored in `.env`.",
        "- **Deployment coordinates** — database/broker/Qdrant hosts and ports, queue names,",
        "  bind paths, evidence bucket and endpoints, `ENVIRONMENT`. Changing these from the",
        "  UI can move the process somewhere it cannot come back from.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="fail when the page is stale"
    )
    args = parser.parse_args()

    rendered = render()
    if args.check:
        current = TARGET.read_text() if TARGET.exists() else ""
        if current.strip() != rendered.strip():
            print(
                f"[!] {TARGET.relative_to(REPO_ROOT)} is stale; regenerate it.",
                file=sys.stderr,
            )
            return 1
        print("[+] admin settings reference is current")
        return 0

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(rendered)
    print(f"[+] wrote {TARGET.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

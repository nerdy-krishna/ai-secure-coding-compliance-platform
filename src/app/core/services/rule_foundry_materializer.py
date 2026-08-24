"""Private tool-native materialization for verified foundry rules."""

from __future__ import annotations

import json
import shutil
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Sequence

from app.core.services.rule_foundry_runtime import ActiveFoundryRule


@asynccontextmanager
async def materialize_gitleaks_rules(
    rules: Sequence[ActiveFoundryRule],
) -> AsyncIterator[Path]:
    root = Path(tempfile.mkdtemp(prefix="sccap_foundry_gitleaks_"))
    config = root / "rules.toml"
    try:
        lines = ["title = \"SCCAP signed tenant Rule Foundry pack\""]
        for active in rules:
            rule = active.as_gitleaks_rule()
            lines.extend(
                (
                    "",
                    "[[rules]]",
                    f"id = {json.dumps(str(rule['id']))}",
                    f"description = {json.dumps(str(rule.get('description') or rule['id']))}",
                    f"regex = {json.dumps(str(rule['regex']))}",
                )
            )
            if rule.get("secret_group") is not None:
                lines.append(f"secretGroup = {int(rule['secret_group'])}")
            keywords = rule.get("keywords") or []
            if keywords:
                lines.append(
                    "keywords = ["
                    + ",".join(json.dumps(str(value)) for value in keywords[:50])
                    + "]"
                )
        config.write_text("\n".join(lines) + "\n", encoding="utf-8")
        yield config
    finally:
        shutil.rmtree(root, ignore_errors=True)

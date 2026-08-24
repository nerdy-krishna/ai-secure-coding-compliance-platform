# src/app/core/services/semgrep_ingestion/materializer.py
import logging
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import yaml

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


@asynccontextmanager
async def materialize_rules(rules: list[db_models.SemgrepRule] | list[Any]) -> AsyncIterator[Path]:
    """
    Write each rule's raw_yaml into a temp directory as individual YAML files.
    Yields the directory Path. Cleans up on exit regardless of errors.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="sccap_semgrep_"))
    try:
        for rule in rules:
            fname = tmpdir / f"{rule.namespaced_id.replace('/', '_')}.yaml"
            rule_doc = {"rules": [rule.raw_yaml]}
            fname.write_text(
                yaml.safe_dump(rule_doc, default_flow_style=False), encoding="utf-8"
            )
        logger.debug(
            "semgrep.materializer.written",
            extra={"rule_count": len(rules), "tmpdir": str(tmpdir)},
        )
        yield tmpdir
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)

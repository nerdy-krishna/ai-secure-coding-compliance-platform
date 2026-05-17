"""Ingest the bundled CWE Essentials / ISVS RAG corpora into the vector store.

Framework Expansion #60 / #62 ship a RAG corpus for CWE Essentials and
ISVS inside the repository (`app/data/<framework>_corpus.csv`, generated
from the concern-area markdown by `scripts/build_corpus.py`). Unlike the
admin CSV-upload flow, this path is *raw* — it skips the paid LLM
enrichment pass — because the bundled corpus is already authored in the
`**Vulnerability Pattern**` / `**Secure Pattern**` layout the scan
agents parse. That makes it free and fast enough to run unattended on
app startup.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict, List

from app.infrastructure.rag.base import VectorStore

logger = logging.getLogger(__name__)

# `app/data/` — three levels up from this module (rag → infrastructure → app).
_DATA_DIR = Path(__file__).resolve().parents[2] / "data"

# framework_name → bundled corpus CSV filename under `app/data/`.
BUNDLED_CORPORA: Dict[str, str] = {
    "cwe_essentials": "cwe_essentials_corpus.csv",
    "isvs": "isvs_corpus.csv",
}


def _read_corpus_csv(csv_path: Path) -> List[Dict[str, str]]:
    with open(csv_path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def ingest_bundled_corpus(rag_service: VectorStore, framework: str) -> int:
    """Ingest one bundled corpus into the guidelines collection.

    Idempotent: the framework's existing documents are deleted first, so
    a re-run replaces rather than duplicates. Documents are tagged
    `scan_ready=True` and carry the `concern_area` facet so the CWE /
    ISVS agents retrieve them. Returns the document count ingested
    (0 if the bundled CSV is missing or empty).
    """
    csv_path = _DATA_DIR / BUNDLED_CORPORA[framework]
    if not csv_path.exists():
        logger.warning("bundled corpus CSV missing: %s", csv_path)
        return 0
    rows = _read_corpus_csv(csv_path)
    if not rows:
        return 0
    documents = [row["document"] for row in rows]
    metadatas = [
        {
            "framework_name": framework,
            "concern_area": row["concern_area"],
            "scan_ready": True,
            "source": "bundled",
        }
        for row in rows
    ]
    ids = [f"{framework}::{row['id']}" for row in rows]
    rag_service.delete_by_framework(framework)
    rag_service.add(documents=documents, metadatas=metadatas, ids=ids)
    logger.info(
        "bundled corpus ingested",
        extra={"framework": framework, "docs": len(rows)},
    )
    return len(rows)


def ingest_all_bundled_corpora(
    rag_service: VectorStore, *, only_if_empty: bool = False
) -> Dict[str, int]:
    """Ingest every bundled corpus; returns ``{framework: doc_count}``.

    When ``only_if_empty`` (the startup-hook path), a framework that
    already has documents in the store is left untouched. A failure on
    one framework is logged and does not abort the others.
    """
    result: Dict[str, int] = {}
    for framework in BUNDLED_CORPORA:
        try:
            if only_if_empty:
                existing = len(rag_service.get_by_framework(framework).get("ids", []))
                if existing:
                    logger.info(
                        "bundled corpus already present; skipping",
                        extra={"framework": framework, "docs": existing},
                    )
                    result[framework] = existing
                    continue
            result[framework] = ingest_bundled_corpus(rag_service, framework)
        except Exception:
            logger.error(
                "bundled corpus ingest failed",
                extra={"framework": framework},
                exc_info=True,
            )
            result[framework] = 0
    return result

"""Ingest the bundled ASVS / CWE Essentials / ISVS RAG corpora.

Three frameworks ship a RAG corpus inside the repository
(`app/data/<framework>_corpus.csv`, rendered from hand-authored
per-domain enriched YAML by `scripts/build_enriched_corpus.py`). Unlike
the admin CSV-upload flow, this path is *raw* — it skips the paid LLM
enrichment pass — because the bundled corpus is already authored in the
enriched `**Vulnerability Pattern**` / `**Secure Pattern**` /
`[[LANG PATTERNS]]` layout the scan agents parse. That makes it free
and fast enough to run unattended on app startup.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict, List, Optional

from app.infrastructure.rag.base import VectorStore

logger = logging.getLogger(__name__)

# `app/data/` — three levels up from this module (rag → infrastructure → app).
_DATA_DIR = Path(__file__).resolve().parents[2] / "data"

# framework_name → bundled corpus spec. `csv` is the filename under
# `app/data/`; `facet` is the metadata column the framework's agents
# filter retrieval on — CWE Essentials / ISVS key on `concern_area`,
# ASVS keys on `control_family`.
BUNDLED_CORPORA: Dict[str, Dict[str, str]] = {
    "cwe_essentials": {"csv": "cwe_essentials_corpus.csv", "facet": "concern_area"},
    "isvs": {"csv": "isvs_corpus.csv", "facet": "concern_area"},
    "asvs": {"csv": "asvs_corpus.csv", "facet": "control_family"},
}


# Upsert chunk size — stays at or under the embedder's per-batch cap.
_ADD_BATCH = 256


def _read_corpus_csv(csv_path: Path) -> List[Dict[str, str]]:
    with open(csv_path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def ingest_bundled_corpus(rag_service: VectorStore, framework: str) -> int:
    """Ingest one bundled corpus into the guidelines collection.

    Idempotent: the framework's existing documents are deleted first, so
    a re-run replaces rather than duplicates. Documents are tagged
    `scan_ready=True` and carry the framework's retrieval facet so its
    agents retrieve them. Returns the document count ingested (0 if the
    bundled CSV is missing or empty).
    """
    spec = BUNDLED_CORPORA[framework]
    facet = spec["facet"]
    csv_path = _DATA_DIR / spec["csv"]
    if not csv_path.exists():
        logger.warning("bundled corpus CSV missing: %s", csv_path)
        return 0
    rows = _read_corpus_csv(csv_path)
    if not rows:
        return 0
    documents = [row["document"] for row in rows]
    # RAG lever 1 — when the corpus carries an `embed_text` column
    # (concept-only text, no code), embed THAT instead of the code-heavy
    # `document`. Only used when every row supplies it; a corpus without
    # the column falls back to embedding the document.
    embed_texts: Optional[List[str]] = None
    if all(row.get("embed_text") for row in rows):
        embed_texts = [row["embed_text"] for row in rows]
    metadatas = [
        {
            "framework_name": framework,
            facet: row[facet],
            "scan_ready": True,
            "source": "bundled",
        }
        for row in rows
    ]
    ids = [f"{framework}::{row['id']}" for row in rows]
    rag_service.delete_by_framework(framework)
    # The embedder caps a batch at 256 texts; a large corpus (ASVS ships
    # ~345 requirements) is upserted in chunks.
    for start in range(0, len(rows), _ADD_BATCH):
        end = start + _ADD_BATCH
        rag_service.add(
            documents=documents[start:end],
            metadatas=metadatas[start:end],
            ids=ids[start:end],
            embed_texts=embed_texts[start:end] if embed_texts is not None else None,
        )
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

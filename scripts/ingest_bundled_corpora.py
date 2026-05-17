"""CLI: ingest the bundled CWE Essentials / ISVS RAG corpora.

Run inside the app container:

    docker compose exec app python scripts/ingest_bundled_corpora.py

Free and fast — it uses the raw ingest path (no paid LLM enrichment),
since the bundled corpora are already authored in the pattern format
the scan agents parse. Idempotent: re-running replaces a framework's
documents rather than duplicating them.

The app also runs this automatically on startup for any bundled corpus
that is not yet present (see the lifespan hook in `app/main.py`); this
script is the manual escape hatch / re-ingest path.
"""

from __future__ import annotations


def main() -> int:
    from app.infrastructure.rag.bundled_corpus import ingest_all_bundled_corpora
    from app.infrastructure.rag.factory import get_vector_store

    store = get_vector_store()
    results = ingest_all_bundled_corpora(store)
    for framework, count in sorted(results.items()):
        print(f"{framework}: {count} documents ingested")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

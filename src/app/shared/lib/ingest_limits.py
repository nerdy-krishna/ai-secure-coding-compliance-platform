"""One set of ingestion limits for every way a submission arrives.

Uploads, archives and git clones each carried their own cap (10 MB/200 MB for
uploads, 5 MB/500 MB for clones), so whether a large file was scanned depended on
how it was submitted. These constants are the single source; the env overrides let an
operator raise them for a repository that legitimately contains large sources.
"""

from __future__ import annotations

import os


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


#: Per-file ceiling. Above this a file is recorded in coverage as truncated rather
#: than scanned, because Semgrep parse time grows superlinearly on large inputs.
MAX_FILE_BYTES: int = _env_int("INGEST_MAX_FILE_BYTES", 10 * 1024 * 1024)

#: Whole-submission ceiling.
MAX_TOTAL_BYTES: int = _env_int("INGEST_MAX_TOTAL_BYTES", 500 * 1024 * 1024)

#: How many files one submission may carry.
MAX_FILES: int = _env_int("INGEST_MAX_FILES", 20_000)

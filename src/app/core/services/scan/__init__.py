"""Scan service package — split out of `scan_service.py` (split-scan-service run, 2026-04-26).

Three focused services:
- `ScanSubmissionService` — new-scan creation (uploads / git / archive) and the outbox enqueue.
- `ScanLifecycleService` — post-creation state transitions (approve, decline, cancel, resume, restart).
- `ScanQueryService` — read paths (status / result / lists / search / LLM interactions) plus superuser-only deletes.

Each service is wired via its own `Depends(get_*_service)` factory in `app/api/v1/dependencies.py`.
"""

from app.core.services.scan.lifecycle import ScanLifecycleService
from app.core.services.scan.query import ScanQueryService
from app.core.services.scan.submission import ScanSubmissionService

__all__ = [
    "ScanSubmissionService",
    "ScanLifecycleService",
    "ScanQueryService",
]

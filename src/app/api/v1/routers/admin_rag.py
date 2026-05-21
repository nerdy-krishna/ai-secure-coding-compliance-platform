# src/app/api/v1/routers/admin_rag.py
"""Admin RAG management.

DANGEROUS FUNCTIONALITY (V15.1.5):
- ingest_documents (line 314) and start_preprocessing_job (line 110) read
  attacker-influenced UploadFile bytes via pandas.read_csv. Cells are stored
  in the DB and re-rendered to admins later -- DOWNSTREAM RENDERERS MUST
  escape leading =, +, -, @ to prevent CSV/formula injection.
- ingest_security_standard (line 424) accepts an attacker-influenced URL for
  proactive-controls/cheatsheets and forwards to
  SecurityStandardsService.ingest_*_github(). SSRF/redirect concerns are
  enforced both at the router boundary (host/scheme allowlist) and inside
  SecurityStandardsService (allowlist host == github.com, disable redirects,
  bound response size).

Protection requirements for raw_content (V14.1.2):
(a) MUST NOT be logged in any handler in this module.
(b) SHOULD be deleted from the rag_jobs row by a scheduled task once the
    job has been COMPLETED for 30 days (TODO: follow-up).
(c) MUST be stored encrypted at rest if and only if the upload originates
    from a tenant-scoped path (currently always admin so plaintext acceptable
    today, but document the expectation).
"""

import asyncio
import logging
import math
import re
import uuid
import io
from typing import Any, Dict, List, cast, Optional
from urllib.parse import urlparse
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    status,
    BackgroundTasks,
)
import pandas as pd
from pydantic import BaseModel, Field

from app.api.v1.dependencies import (
    get_framework_repository,
    get_rag_job_repository,
    get_rag_preprocessor_service,
    get_security_standards_service,
)
from app.api.v1 import models as api_models
from app.core.services.security_standards_service import SecurityStandardsService
from app.core.schemas import (
    EnrichedDocument,
    PreprocessingResponse,
    RAGJobStartResponse,
    RAGJobStatusResponse,
)
from app.core.services.rag_preprocessor_service import RAGPreprocessorService
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.framework_repo import FrameworkRepository
from app.infrastructure.database.repositories.rag_job_repo import RAGJobRepository
from app.infrastructure.rag.rag_client import get_rag_service, RAGService
from app.api.v1.models import RAGDocumentDeleteRequest

logger = logging.getLogger(__name__)
rag_router = APIRouter(prefix="/rag", tags=["Admin: RAG Management"])

# V05.1.1 / V05.2.1: hard caps for upload-accepting endpoints.
# Maximum CSV/binary upload size accepted (25 MB).
MAX_RAG_UPLOAD_BYTES = 25 * 1024 * 1024
# Maximum JSON upload size accepted (5 MB).
MAX_RAG_JSON_BYTES = 5 * 1024 * 1024
# V01.5.2: cap rows when parsing CSV with pandas.
MAX_RAG_CSV_ROWS = 100_000
# V01.5.2: maximum length per CSV cell value.
MAX_RAG_CSV_CELL_BYTES = 10 * 1024
# V05.3.2: framework_name allowlist regex.
_FRAMEWORK_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# V02.2.1: closed allowlist of standard_type values.
_ALLOWED_STANDARD_TYPES = {
    "asvs",
    "proactive-controls",
    "cheatsheets",
    "llm-top10",
    "agentic-top10",
}
# V15.4.1: per-framework asyncio locks to serialize delete-then-add ingestion.
_rag_ingest_locks: Dict[str, asyncio.Lock] = {}


def _validate_framework_name(name: str) -> str:
    """V05.3.2: enforce framework_name allowlist on the server."""
    if not isinstance(name, str) or not _FRAMEWORK_NAME_RE.fullmatch(name):
        raise HTTPException(
            status_code=400,
            detail="framework_name must match [A-Za-z0-9_-]{1,64}",
        )
    return name


def _validate_github_url(url: str) -> str:
    """V01.3.6 / V15.2.5: SSRF allowlist for GitHub-only ingestion URLs."""
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid URL.",
        )
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ("github.com", "raw.githubusercontent.com")
        or parsed.username
        or parsed.password
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Only https://github.com or https://raw.githubusercontent.com "
                "URLs are accepted."
            ),
        )
    return url


async def _read_capped(file: UploadFile, cap: int) -> bytes:
    """V05.2.1: stream UploadFile in chunks; abort if total exceeds cap."""
    chunks: List[bytes] = []
    total = 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds {cap} bytes",
            )
        chunks.append(chunk)
    return b"".join(chunks)


class ReprocessRequest(BaseModel):
    framework_name: str = Field(
        min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"
    )
    target_languages: List[str] = Field(default_factory=list, max_length=64)
    llm_config_id: uuid.UUID


@rag_router.post("/preprocess/reprocess", response_model=RAGJobStartResponse)
async def reprocess_framework(
    request: ReprocessRequest,
    user: db_models.User = Depends(current_superuser),
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
    preprocessor: RAGPreprocessorService = Depends(get_rag_preprocessor_service),
):
    """
    Restart a preprocessing job using the original content from the latest completed job
    for the given framework. This enables "Editing" without re-uploading the file.
    """
    framework_name = _validate_framework_name(request.framework_name)
    logger.info(
        "admin.rag.reprocess_started",
        extra={"actor_id": str(user.id), "framework_name": framework_name},
    )
    latest_job = await job_repo.get_latest_job_for_framework(framework_name, user.id)

    if not latest_job or not latest_job.raw_content:
        raise HTTPException(
            status_code=404,
            detail=f"No previous completed job found for framework '{framework_name}' with content. Please upload the file again.",
        )

    # Calculate new cost estimate with potentially new parameters
    estimated_cost = await preprocessor.estimate_cost(
        latest_job.raw_content,
        request.llm_config_id,
        request.target_languages,
        previous_job_state=latest_job,
    )

    # Create a NEW job with the OLD content
    new_job = await job_repo.create_job(
        user_id=user.id,
        framework_name=framework_name,
        llm_config_id=request.llm_config_id,
        file_hash=latest_job.original_file_hash,
    )

    # Store the content and update status
    await job_repo.update_job(
        new_job.id,
        {
            "raw_content": latest_job.raw_content,
            "status": "PENDING_APPROVAL",
            "estimated_cost": estimated_cost,
        },
    )

    message = "Cost re-estimated for updated configuration. Please approve to start processing."

    return RAGJobStartResponse(
        job_id=new_job.id,
        framework_name=new_job.framework_name,
        status="PENDING_APPROVAL",
        estimated_cost=estimated_cost,
        message=message,
    )


@rag_router.post("/preprocess/start", response_model=RAGJobStartResponse)
async def start_preprocessing_job(
    file: UploadFile = File(...),
    llm_config_id: uuid.UUID = Form(...),
    framework_name: str = Form(
        ..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"
    ),
    target_languages: List[str] = Form([]),
    # V14.2.8 — explicit consent for raw upload retention. Defaults to false
    # so a missing field is treated as "do not store the bytes."
    raw_content_retention_consent: bool = Form(False),
    user: db_models.User = Depends(current_superuser),
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
    preprocessor: RAGPreprocessorService = Depends(get_rag_preprocessor_service),
):
    """
    Step 1: Starts a new RAG preprocessing job by hashing the file, checking for duplicates,
    calculating the cost, and returning a job ID for approval.

    Server enforces a maximum upload size of MAX_RAG_UPLOAD_BYTES (25 MB);
    requests exceeding this return HTTP 413. The server logs a security event
    and returns 400 when the file fails magic-byte or schema validation.
    """
    framework_name = _validate_framework_name(framework_name)
    contents = await _read_capped(file, MAX_RAG_UPLOAD_BYTES)
    file_hash = job_repo.hash_content(contents)
    logger.info(
        "admin.rag.preprocess_started",
        extra={
            "actor_id": str(user.id),
            "framework_name": framework_name,
            "file_hash": file_hash,
            "size_bytes": len(contents),
        },
    )

    # Always treat as a new job and calculate the cost.
    job = await job_repo.create_job(
        user_id=user.id,
        framework_name=framework_name,
        llm_config_id=llm_config_id,
        file_hash=file_hash,
        raw_content_retention_consent=raw_content_retention_consent,
    )
    # V14.2.8 — only persist raw upload bytes when the operator explicitly
    # consented; otherwise leave `raw_content` NULL.
    if raw_content_retention_consent:
        await job_repo.update_job(job.id, {"raw_content": contents})
    else:
        logger.info(
            "admin.rag.raw_content_suppressed_no_consent",
            extra={
                "job_id": str(job.id),
                "framework_name": framework_name,
                "size_bytes": len(contents),
            },
        )

    estimated_cost = await preprocessor.estimate_cost(
        contents, llm_config_id, target_languages
    )

    await job_repo.update_job(
        job.id, {"status": "PENDING_APPROVAL", "estimated_cost": estimated_cost}
    )
    message = "Cost estimated. Please approve to start processing."

    final_job_state = await job_repo.get_job_by_id(job.id, user.id)
    if not final_job_state:
        raise HTTPException(
            status_code=500, detail="Failed to retrieve job state after creation."
        )

    return RAGJobStartResponse(
        job_id=final_job_state.id,
        framework_name=final_job_state.framework_name,
        status=final_job_state.status,
        estimated_cost=final_job_state.estimated_cost,
        message=message,
    )


@rag_router.post("/preprocess/{job_id}/approve", status_code=status.HTTP_202_ACCEPTED)
async def approve_preprocessing_job(
    job_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    user: db_models.User = Depends(current_superuser),
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
    preprocessor: RAGPreprocessorService = Depends(get_rag_preprocessor_service),
):
    """
    Step 2: Approves and starts the actual LLM processing for a job as a background task.
    """
    logger.info(
        "admin.rag.preprocess_approved",
        extra={"actor_id": str(user.id), "job_id": str(job_id)},
    )
    job = await job_repo.get_job_by_id(job_id, user.id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    if job.status != "PENDING_APPROVAL":
        raise HTTPException(
            status_code=400,
            detail=f"Job is not awaiting approval. Status: {job.status}",
        )

    # If the job already has processed documents (from a duplicate run), we can complete it immediately.
    if job.processed_documents:
        await job_repo.update_job(job_id, {"status": "COMPLETED"})
        return {"message": "Existing job result approved. You can now ingest the data."}

    raw_content = job.raw_content
    if not raw_content:
        await job_repo.update_job(
            job_id,
            {"status": "FAILED", "error_message": "Original file content is missing."},
        )
        raise HTTPException(
            status_code=400,
            detail="Cannot process job, original file content is missing.",
        )

    await job_repo.update_job(job_id, {"status": "PROCESSING"})

    # Run the time-consuming task in the background
    background_tasks.add_task(
        preprocessor.run_preprocessing_job, job_id, user.id, raw_content
    )

    return {"message": "Job approved. Processing has started in the background."}


@rag_router.get("/preprocess/{job_id}/status", response_model=RAGJobStatusResponse)
async def get_preprocessing_job_status(
    job_id: uuid.UUID,
    user: db_models.User = Depends(current_superuser),
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
):
    """
    Step 3: Polls for the status and result of a preprocessing job.
    """
    job = await job_repo.get_job_by_id(job_id, user.id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    return RAGJobStatusResponse(
        job_id=job.id,
        framework_name=job.framework_name,
        status=job.status,
        estimated_cost=job.estimated_cost,
        actual_cost=job.actual_cost,
        processed_documents=(
            [EnrichedDocument(**doc) for doc in job.processed_documents]
            if job.processed_documents
            else None
        ),
        error_message=job.error_message,
    )


# --- Direct Ingestion and Management Endpoints ---


@rag_router.post("/ingest-processed", status_code=status.HTTP_201_CREATED)
async def ingest_processed_documents(
    payload: PreprocessingResponse,
    user: db_models.User = Depends(current_superuser),
    rag_service: RAGService = Depends(get_rag_service),
    framework_repo: FrameworkRepository = Depends(get_framework_repository),
):
    """
    Deletes all existing documents for a framework and ingests the new,
    processed documents. This is the final step after a job is complete.
    Also creates a Framework database record if one doesn't already exist.
    """
    framework_name = _validate_framework_name(payload.framework_name)
    logger.info(
        "admin.rag.ingest_processed.start",
        extra={"actor_id": str(user.id), "framework_name": framework_name},
    )
    # V15.4.1: serialize concurrent ingestions per framework_name to avoid
    # torn shared-cache updates between delete_by_framework and add().
    lock = _rag_ingest_locks.setdefault(framework_name, asyncio.Lock())
    try:
        async with lock:
            documents = payload.processed_documents

            rag_service.delete_by_framework(framework_name)

            # Namespace IDs with framework name to avoid collisions in the shared collection.
            # E.g., "CWE-79" in a custom framework would collide with "CWE-79" in OWASP ASVS.
            ids = [f"{framework_name}::{doc.id}" for doc in documents]
            docs_to_add = [doc.enriched_content for doc in documents]
            metadatas = [doc.metadata for doc in documents]

            for i, meta in enumerate(metadatas):
                meta["framework_name"] = framework_name
                meta["scan_ready"] = payload.scan_ready
                meta["original_id"] = documents[i].id

            # Sanitize metadata: ChromaDB rejects NaN, None, and non-primitive values.
            # Pandas DataFrames produce NaN for empty cells which silently breaks ChromaDB add().
            sanitized_metadatas = []
            for meta in metadatas:
                clean = {}
                for k, v in meta.items():
                    if v is None:
                        clean[k] = ""
                    elif isinstance(v, float) and math.isnan(v):
                        clean[k] = ""
                    elif isinstance(v, (str, int, float, bool)):
                        clean[k] = v
                    else:
                        clean[k] = str(v)
                sanitized_metadatas.append(clean)

            logger.info(
                "admin.rag.ingest_processed",
                extra={
                    "framework_name": framework_name,
                    "id_count": len(ids),
                    "metadata_keys": (
                        list(sanitized_metadatas[0].keys())
                        if sanitized_metadatas
                        else []
                    ),
                },
            )

            rag_service.add(
                documents=docs_to_add, metadatas=sanitized_metadatas, ids=ids
            )

            # Auto-create a Framework DB record so it appears in the Knowledge Base
            existing_framework = await framework_repo.get_framework_by_name(
                framework_name
            )
            if not existing_framework:
                framework_data = api_models.FrameworkCreate(
                    name=framework_name,
                    description=f"Custom framework with {len(documents)} enriched documents.",
                )
                await framework_repo.create_framework(framework_data)
                logger.info(
                    "admin.rag.framework_auto_created",
                    extra={"framework_name": framework_name},
                )

            return {
                "message": f"Successfully deleted old documents and ingested {len(documents)} new processed documents for framework '{framework_name}'."
            }
    except HTTPException:
        raise
    except Exception:
        logger.error(
            "admin.rag.ingest_processed.failed",
            extra={"framework_name": framework_name},
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail="An error occurred during processed ingestion.",
        )


@rag_router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_documents(
    framework_name: str = Form(
        ..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"
    ),
    file: UploadFile = File(...),
    user: db_models.User = Depends(current_superuser),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    (Legacy) Ingests raw documents from a CSV file directly without preprocessing.

    Server enforces a maximum upload size of MAX_RAG_UPLOAD_BYTES (25 MB);
    requests exceeding this return HTTP 413. The CSV must contain `id` and
    `document` columns and is parsed with row/cell caps. The server logs a
    security event and returns 400 when the file fails magic-byte or schema
    validation.
    """
    framework_name = _validate_framework_name(framework_name)
    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A CSV file with a valid filename is required.",
        )
    # V05.2.2: confirm declared content_type lines up with CSV expectation.
    if file.content_type and file.content_type not in (
        "text/csv",
        "application/vnd.ms-excel",
        "application/octet-stream",
        "text/plain",
    ):
        raise HTTPException(
            status_code=400,
            detail="File content does not match expected type",
        )
    try:
        contents = await _read_capped(file, MAX_RAG_UPLOAD_BYTES)
        # V05.2.2: lightweight magic-byte / structural check on the head of
        # the file -- a binary blob renamed .csv would not look like CSV.
        head = contents[:1024].decode("utf-8", errors="replace")
        first_line = head.splitlines()[0] if head else ""
        if "," not in first_line:
            raise HTTPException(
                status_code=400,
                detail="File content does not match expected type",
            )
        logger.info(
            "admin.rag.ingest_started",
            extra={
                "actor_id": str(user.id),
                "framework_name": framework_name,
                "size_bytes": len(contents),
            },
        )
        csv_file = io.StringIO(contents.decode("utf-8"))
        # V01.5.2: cap row count, force string dtypes, fail on bad lines.
        df = pd.read_csv(
            csv_file,
            dtype=str,
            on_bad_lines="error",
            engine="python",
            nrows=MAX_RAG_CSV_ROWS,
        )

        if "id" not in df.columns or "document" not in df.columns:
            raise HTTPException(
                status_code=400,
                detail="CSV must contain 'id' and 'document' columns.",
            )

        ids = df["id"].astype(str).tolist()
        documents = df["document"].astype(str).tolist()
        metadatas_raw = df.drop(columns=["id", "document"]).to_dict("records")
        metadatas = cast(List[Dict[str, Any]], metadatas_raw)

        # V01.5.2: reject rows where any cell exceeds the configured cap.
        for metadata in metadatas:
            for k, v in metadata.items():
                if isinstance(v, str) and len(v) > MAX_RAG_CSV_CELL_BYTES:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"CSV cell for '{k}' exceeds {MAX_RAG_CSV_CELL_BYTES} bytes"
                        ),
                    )
            metadata["framework_name"] = framework_name
            metadata["scan_ready"] = True

        rag_service.add(documents=documents, metadatas=metadatas, ids=ids)
        return {
            "message": f"Successfully ingested {len(documents)} documents for framework '{framework_name}'."
        }

    except HTTPException:
        raise
    except Exception:
        logger.error(
            "admin.rag.ingest.failed",
            extra={"framework_name": framework_name},
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during ingestion.",
        )


@rag_router.get("/frameworks/{framework_name}", response_model=dict)
async def get_documents_for_framework(
    framework_name: str,
    user: db_models.User = Depends(current_superuser),
    rag_service: RAGService = Depends(get_rag_service),
):
    """Retrieves all documents associated with a specific framework."""
    framework_name = _validate_framework_name(framework_name)
    try:
        return rag_service.get_by_framework(framework_name)
    except Exception:
        logger.error(
            "admin.rag.get_by_framework.failed",
            extra={"framework_name": framework_name},
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Failed to retrieve documents from RAG service."
        )


@rag_router.delete("/documents", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rag_documents(
    request: RAGDocumentDeleteRequest,
    user: db_models.User = Depends(current_superuser),
    rag_service: RAGService = Depends(get_rag_service),
):
    """Deletes one or more documents from the RAG knowledge base by their IDs."""
    if not request.document_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No document IDs provided for deletion.",
        )
    logger.info(
        "admin.rag.docs_deleted",
        extra={
            "actor_id": str(user.id),
            "id_count": len(request.document_ids),
        },
    )
    try:
        rag_service.delete(ids=request.document_ids)
    except Exception:
        logger.error(
            "admin.rag.delete.failed",
            extra={"id_count": len(request.document_ids)},
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Failed to delete documents from RAG service."
        )


# --- NEW Security Standards Ingestion Endpoints ---


@rag_router.get("/ingest/stats", response_model=Dict[str, int])
async def get_rag_stats(
    rag_service: RAGService = Depends(get_rag_service),
    user: db_models.User = Depends(current_superuser),
):
    """
    Get document counts for standard security frameworks.
    """
    if not rag_service:
        raise HTTPException(status_code=503, detail="RAG Service not available")

    return rag_service.get_framework_stats()


@rag_router.post(
    "/ingest/standards/{standard_type}", status_code=status.HTTP_201_CREATED
)
async def ingest_security_standard(
    standard_type: str,
    file: Optional[UploadFile] = File(None),
    url: Optional[str] = Form(None),
    user: db_models.User = Depends(current_superuser),
    standards_service: SecurityStandardsService = Depends(
        get_security_standards_service
    ),
):
    """
    Ingests a security standard into the RAG knowledge base.

    - **standard_type**: 'asvs', 'proactive-controls', 'cheatsheets',
      'llm-top10', 'agentic-top10'.
    - **asvs**: Requires 'file' (CSV, max MAX_RAG_UPLOAD_BYTES = 25 MB).
    - **proactive-controls**: Requires 'url' (https://github.com/... only).
    - **cheatsheets**: Requires 'url' (https://github.com/... only).
    - **llm-top10**: Requires 'file' (JSON, max MAX_RAG_JSON_BYTES = 5 MB,
      shape of `data/owasp/llm_top10_2025.json`).
    - **agentic-top10**: Requires 'file' (JSON, max MAX_RAG_JSON_BYTES = 5 MB,
      shape of `data/owasp/agentic_top10_2026.json`).

    Server logs a security event and returns 400 when the file fails magic-byte
    or schema validation, 413 when size limits are exceeded.
    """
    # V02.2.1 / V05.3.2: enforce closed allowlist of standard_type values.
    if standard_type not in _ALLOWED_STANDARD_TYPES:
        raise HTTPException(
            status_code=400, detail=f"Unsupported standard type: {standard_type}"
        )
    logger.info(
        "admin.rag.standard_ingest_started",
        extra={
            "actor_id": str(user.id),
            "standard_type": standard_type,
        },
    )
    try:
        if standard_type == "asvs":
            if not file:
                raise HTTPException(
                    status_code=400, detail="ASVS requires a CSV file upload."
                )
            if not file.filename or not file.filename.endswith(".csv"):
                raise HTTPException(
                    status_code=400, detail="ASVS file must be a CSV file."
                )
            # V05.2.2: validate declared content_type for CSV.
            if file.content_type and file.content_type not in (
                "text/csv",
                "application/vnd.ms-excel",
                "application/octet-stream",
                "text/plain",
            ):
                raise HTTPException(
                    status_code=400,
                    detail="File content does not match expected type",
                )
            return await standards_service.ingest_asvs_csv(file, user_id=user.id)

        elif standard_type == "proactive-controls":
            if not url:
                raise HTTPException(
                    status_code=400, detail="Proactive Controls requires a GitHub URL."
                )
            url = _validate_github_url(url)
            return await standards_service.ingest_proactive_controls_github(
                url, user_id=user.id
            )

        elif standard_type == "cheatsheets":
            if not url:
                raise HTTPException(
                    status_code=400, detail="Cheatsheets requires a GitHub URL."
                )
            url = _validate_github_url(url)
            return await standards_service.ingest_cheatsheets_github(
                url, user_id=user.id
            )

        elif standard_type == "llm-top10":
            if not file:
                raise HTTPException(
                    status_code=400,
                    detail="OWASP LLM Top-10 requires a JSON file upload.",
                )
            # V05.2.2: validate declared content_type for JSON.
            if file.content_type and file.content_type not in (
                "application/json",
                "text/json",
                "application/octet-stream",
                "text/plain",
            ):
                raise HTTPException(
                    status_code=400,
                    detail="File content does not match expected type",
                )
            return await standards_service.ingest_owasp_top10_json(
                file,
                framework_name="llm_top10",
                expected_control_family="LLM Security",
                user_id=user.id,
            )

        elif standard_type == "agentic-top10":
            if not file:
                raise HTTPException(
                    status_code=400,
                    detail="OWASP Agentic Top-10 requires a JSON file upload.",
                )
            # V05.2.2: validate declared content_type for JSON.
            if file.content_type and file.content_type not in (
                "application/json",
                "text/json",
                "application/octet-stream",
                "text/plain",
            ):
                raise HTTPException(
                    status_code=400,
                    detail="File content does not match expected type",
                )
            return await standards_service.ingest_owasp_top10_json(
                file,
                framework_name="agentic_top10",
                expected_control_family="Agentic Security",
                user_id=user.id,
            )

        else:
            # Defensive fallback; the allowlist check above should make this
            # branch unreachable.
            raise HTTPException(
                status_code=400, detail=f"Unsupported standard type: {standard_type}"
            )

    except HTTPException as e:
        raise e
    except Exception:
        logger.error(
            "admin.rag.standard_ingest.failed",
            extra={"standard_type": standard_type},
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Failed to ingest standard.")

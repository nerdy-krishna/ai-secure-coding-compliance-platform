import asyncio
import os
from unittest.mock import AsyncMock, MagicMock
from app.core.services.security_standards_service import SecurityStandardsService
from app.infrastructure.rag.rag_client import RAGService
from app.infrastructure.database.repositories.rag_job_repo import RAGJobRepository
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository

# Mock dependencies
mock_rag_service = MagicMock(spec=RAGService)
mock_job_repo = AsyncMock(spec=RAGJobRepository)
mock_llm_config_repo = AsyncMock(spec=LLMConfigRepository)

# Mock get_rag_service at the module level before instantiation if possible,
# or letting it run and patching the instance property.
# get_rag_service is called in __init__.
# So we need to patch app.core.services.security_standards_service.get_rag_service or
# app.infrastructure.rag.rag_client.get_rag_service depending on how it's imported.
# It is imported as: from app.infrastructure.rag.rag_client import get_rag_service

# We will patch it in the test function setup, or better, patch the class property after init if it allows,
# but it calls it IN init.
# So we must patch it before instantiation.

from unittest.mock import patch  # noqa: E402

with patch(
    "app.core.services.security_standards_service.get_rag_service",
    return_value=mock_rag_service,
):
    # Start service
    service = SecurityStandardsService(
        job_repo=mock_job_repo, llm_config_repo=mock_llm_config_repo
    )


async def test_cheatsheets():
    assert isinstance(
        service._fetch_github_files, AsyncMock
    ), "verify_rag_signatures must run with mocked _fetch_github_files"
    print("Testing Cheatsheets Ingestion...")
    # Mock internals
    service._fetch_github_files = AsyncMock(
        return_value=[
            {
                "name": "test.md",
                "type": "file",
                "download_url": "http://test.com/test.md",
            }
        ]
    )
    # Mock httpx response if needed, or mock _fetch_github_files result processing
    # Actually _fetch_github_files returns file nodes, then it iterates and does httpx.get
    # difficult to mock internal httpx.AsyncClient nicely without patching.
    # LETS PATCH ingest_cheatsheets_github argument mainly to see if it accepts user_id

    try:
        # We just want to ensure it accepts user_id now
        await service.ingest_cheatsheets_github("about:blank", user_id=123)
        print("PASS: ingest_cheatsheets_github accepted user_id")
    except TypeError as e:
        print(f"FAIL: ingest_cheatsheets_github raised TypeError: {e}")
    except Exception as e:
        # Valid failure (network etc) is fine, just checking signature
        print(
            f"PASS (Signature Check): ingest_cheatsheets_github accepted user_id, failed later with: {e}"
        )


async def test_proactive_controls():
    assert isinstance(
        service._fetch_github_files, AsyncMock
    ), "verify_rag_signatures must run with mocked _fetch_github_files"
    print("\nTesting Proactive Controls Ingestion...")
    try:
        await service.ingest_proactive_controls_github("about:blank", user_id=123)
        print("PASS: ingest_proactive_controls_github accepted user_id")
    except TypeError as e:
        print(f"FAIL: ingest_proactive_controls_github raised TypeError: {e}")
    except Exception as e:
        print(
            f"PASS (Signature Check): ingest_proactive_controls_github accepted user_id, failed later with: {e}"
        )


if __name__ == "__main__":
    if os.environ.get("SCCAP_ALLOW_DEV_SMOKE_TESTS") != "1":
        raise SystemExit(
            "Disabled outside dev. Set SCCAP_ALLOW_DEV_SMOKE_TESTS=1 to enable."
        )
    asyncio.run(test_cheatsheets())
    asyncio.run(test_proactive_controls())

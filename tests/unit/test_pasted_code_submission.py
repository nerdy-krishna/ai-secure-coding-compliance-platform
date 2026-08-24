"""Focused contracts for the pasted-code scan source."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from fastapi import HTTPException

from app.api.v1.routers.projects import create_scan
from app.core.services.scan.submission import MAX_FILE_BYTES, ScanSubmissionService


class PastedCodeSubmissionTests(unittest.IsolatedAsyncioTestCase):
    def _service(self) -> ScanSubmissionService:
        service = ScanSubmissionService.__new__(ScanSubmissionService)
        service._process_and_launch_scan = AsyncMock(return_value="scan")  # type: ignore[method-assign]
        return service

    async def test_normalizes_pasted_code_into_one_source_file(self) -> None:
        service = self._service()

        result = await service.create_scan_from_pasted_code(
            code="print('hello')\n",
            filename=" src/example.py ",
            project_name="example",
        )

        self.assertEqual(result, "scan")
        service._process_and_launch_scan.assert_awaited_once_with(  # type: ignore[attr-defined]
            files_data=[
                {
                    "path": "src/example.py",
                    "content": "print('hello')\n",
                    "language": "python",
                }
            ],
            source_type="paste",
            project_name="example",
        )

    async def test_rejects_empty_or_nul_pasted_code(self) -> None:
        for code in ("", " \n\t", "print('ok')\x00"):
            with self.subTest(code=repr(code)):
                service = self._service()
                with self.assertRaises(HTTPException) as raised:
                    await service.create_scan_from_pasted_code(
                        code=code,
                        filename="snippet.py",
                    )
                self.assertEqual(raised.exception.status_code, 400)
                service._process_and_launch_scan.assert_not_awaited()  # type: ignore[attr-defined]

    async def test_rejects_unsafe_relative_filename(self) -> None:
        for filename in (
            "",
            "/tmp/code.py",
            "../code.py",
            "src/../code.py",
            "src\\code.py",
        ):
            with self.subTest(filename=filename):
                service = self._service()
                with self.assertRaises(HTTPException) as raised:
                    await service.create_scan_from_pasted_code(
                        code="print('ok')\n",
                        filename=filename,
                    )
                self.assertEqual(raised.exception.status_code, 400)

    async def test_rejects_pasted_code_over_per_file_limit(self) -> None:
        service = self._service()

        with self.assertRaises(HTTPException) as raised:
            await service.create_scan_from_pasted_code(
                code="a" * (MAX_FILE_BYTES + 1),
                filename="snippet.py",
            )

        self.assertEqual(raised.exception.status_code, 413)
        service._process_and_launch_scan.assert_not_awaited()  # type: ignore[attr-defined]

    async def test_scan_router_dispatches_pasted_code_as_exclusive_source(self) -> None:
        scan_id = uuid4()
        project_id = uuid4()
        llm_config_id = uuid4()
        service = AsyncMock(spec=ScanSubmissionService)
        service.create_scan_from_pasted_code.return_value = SimpleNamespace(
            id=scan_id,
            project_id=project_id,
        )

        response = await create_scan(
            service=service,
            llm_repo=AsyncMock(),
            user=SimpleNamespace(id=42),
            project_name="pasted-example",
            scan_type="AUDIT",
            reasoning_llm_config_id=llm_config_id,
            utility_llm_config_id=llm_config_id,
            secondary_reasoning_llm_config_id=None,
            temperature_profiler=0.2,
            temperature_analysis=0.2,
            temperature_consolidation=0.2,
            temperature_analysis_secondary=0.2,
            disable_temperature=True,
            cross_file_validation=False,
            deep_vendor_scan=False,
            frameworks="asvs",
            repo_url=None,
            files=None,
            archive_file=None,
            pasted_code="print('router')\n",
            pasted_filename="snippet.py",
            selected_files=None,
        )

        self.assertEqual(response.scan_id, scan_id)
        service.create_scan_from_pasted_code.assert_awaited_once()
        submitted = service.create_scan_from_pasted_code.await_args.kwargs
        self.assertEqual(submitted["code"], "print('router')\n")
        self.assertEqual(submitted["filename"], "snippet.py")
        service.create_scan_from_uploads.assert_not_awaited()
        service.create_scan_from_git.assert_not_awaited()
        service.create_scan_from_archive.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()

"""Bulk asset import from a CSV file.

Adding a dozen assets one at a time through a modal is not how an inventory starts; a
network team already has a spreadsheet. This reads that spreadsheet, creates what it can,
and reports exactly what it did — created, skipped as a duplicate, rejected with a reason.

Two rules that matter more than the parsing:

- **A duplicate is skipped, never merged or overwritten.** Re-uploading a corrected file
  must not silently mutate assets that already exist and are already authorised.
- **A bad row is rejected with its line number and reason**, and does not abort the
  import. Half a spreadsheet is still progress; silence about the other half is not.
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass, field
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select

from app.assets import models as am
from app.infrastructure.database.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

#: Column order used by the downloadable template and accepted on upload.
TEMPLATE_COLUMNS = (
    "name",
    "kind",
    "owner",
    "environment",
    "host",
    "port",
    "protocol",
    "product",
    "version",
    "authorization_basis",
    "description",
)

#: One example row so the template explains itself. Rows whose name starts with "<" are
#: ignored by the importer, so uploading the template unchanged creates nothing.
EXAMPLE_ROW = (
    "<example — delete this row>",
    "web_app",
    "team-payments",
    "production",
    "portal.example.com",
    "443",
    "https",
    "nginx",
    "1.18.0",
    "owned by us",
    "Customer portal",
)

#: Kind values accepted in the `kind` column; anything else is rejected with the list.
_KINDS = set(am.ASSET_KINDS)


@dataclass
class ImportSummary:
    total: int = 0
    created: list[dict[str, Any]] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "created": len(self.created),
            "duplicates": len(self.duplicates),
            "rejected": len(self.rejected),
            "created_assets": self.created,
            "duplicate_names": self.duplicates,
            "rejected_rows": self.rejected,
        }


def template_csv() -> str:
    """A blank template with one illustrative row."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(TEMPLATE_COLUMNS)
    writer.writerow(EXAMPLE_ROW)
    return buffer.getvalue()


def _clean(value: Optional[str]) -> Optional[str]:
    text = (value or "").strip()
    return text or None


def _parse_port(value: Optional[str]) -> tuple[Optional[int], Optional[str]]:
    text = _clean(value)
    if text is None:
        return None, None
    try:
        port = int(text)
    except ValueError:
        return None, f"port {text!r} is not a number"
    if not 1 <= port <= 65535:
        return None, f"port {port} is out of range"
    return port, None


async def import_csv(
    tenant_id: UUID, content: bytes, *, created_by: Optional[int] = None
) -> dict[str, Any]:
    """Create assets from a CSV file; report every row's fate."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return {
            "error": "the file is not UTF-8 text — save it as CSV UTF-8 and try again"
        }

    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return {"error": "the file has no header row"}
    headers = {(name or "").strip().lower() for name in reader.fieldnames}
    if "name" not in headers:
        return {
            "error": (
                "the file needs a 'name' column. Expected: "
                + ", ".join(TEMPLATE_COLUMNS)
            )
        }

    summary = ImportSummary()
    rows = [
        (line_number, {(key or "").strip().lower(): value for key, value in raw.items()})
        for line_number, raw in enumerate(reader, start=2)
    ]
    candidates = [
        (line, row)
        for line, row in rows
        if _clean(row.get("name")) and not str(_clean(row.get("name"))).startswith("<")
    ]
    if not candidates:
        return summary.as_dict()

    async with AsyncSessionLocal() as db:
        existing = {
            (row or "").strip().lower()
            for row in await db.scalars(
                select(am.Asset.name).where(am.Asset.tenant_id == tenant_id)
            )
        }

    for line_number, row in rows:
        name = _clean(row.get("name"))
        if name is None:
            summary.total += 1
            summary.rejected.append(
                {"line": line_number, "name": None, "reason": "missing name"}
            )
            continue
        if name.startswith("<"):
            # Template example row, or a commented row in a filled-in sheet.
            continue

        summary.total += 1
        if name.lower() in existing:
            summary.duplicates.append(name)
            continue

        kind = (_clean(row.get("kind")) or am.ASSET_WEB_APP).lower()
        if kind not in _KINDS:
            summary.rejected.append(
                {
                    "line": line_number,
                    "name": name,
                    "reason": f"unknown kind {kind!r}; use one of {', '.join(sorted(_KINDS))}",
                }
            )
            continue

        port, port_error = _parse_port(row.get("port"))
        if port_error:
            summary.rejected.append({"line": line_number, "name": name, "reason": port_error})
            continue

        host = _clean(row.get("host"))
        try:
            from app.assets import service as asset_service

            asset = await asset_service.create_asset(
                tenant_id=tenant_id,
                name=name[:200],
                kind=kind,
                description=_clean(row.get("description")),
                owner=_clean(row.get("owner")),
                environment=_clean(row.get("environment")),
                authorization_basis=_clean(row.get("authorization_basis"))
                or "bulk import",
                created_by=created_by,
            )
            if host:
                await asset_service.add_service(
                    tenant_id,
                    asset.id,
                    host=host,
                    port=port,
                    protocol=(_clean(row.get("protocol")) or "https")[:16],
                    product=_clean(row.get("product")),
                    version=_clean(row.get("version")),
                    source="import",
                    confidence="exact" if _clean(row.get("version")) else "heuristic",
                )
        except Exception as exc:  # noqa: BLE001 — one bad row must not stop the import
            logger.warning("import row %s failed", line_number, exc_info=True)
            summary.rejected.append(
                {
                    "line": line_number,
                    "name": name,
                    "reason": f"{type(exc).__name__}: {exc}"[:200],
                }
            )
            continue

        existing.add(name.lower())
        summary.created.append(
            {
                "id": str(asset.id),
                "name": asset.name,
                "kind": asset.kind,
                "host": host,
            }
        )

    return summary.as_dict()

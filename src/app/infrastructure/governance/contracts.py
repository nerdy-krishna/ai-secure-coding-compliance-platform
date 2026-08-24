"""Strict, bounded contracts persisted in signed governance manifests."""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_RECORDS = 10_000


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class StoreActionResult(BaseModel):
    """Only counts, digests, and opaque artifact references may be signed."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    store: Literal["postgres", "object", "qdrant", "observability"]
    kind: Literal["export", "delete"]
    operation_id: uuid.UUID
    matched_count: int = Field(strict=True, ge=0, le=MAX_RECORDS)
    applied_count: int = Field(strict=True, ge=0, le=MAX_RECORDS)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_ref: str = Field(
        min_length=1, max_length=512, pattern=r"^[A-Za-z0-9_./:-]+$"
    )

    @model_validator(mode="after")
    def validate_counts(self) -> "StoreActionResult":
        if self.applied_count > self.matched_count:
            raise ValueError("applied_count cannot exceed matched_count")
        return self


class RetentionActionResult(BaseModel):
    """Typed destructive-retention evidence for non-transactional stores."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    store: Literal["qdrant", "observability", "backups"]
    kind: Literal["delete"] = "delete"
    operation_id: uuid.UUID
    matched_count: int = Field(strict=True, ge=0, le=MAX_RECORDS)
    applied_count: int = Field(strict=True, ge=0, le=MAX_RECORDS)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_ref: str = Field(
        min_length=1, max_length=512, pattern=r"^[A-Za-z0-9_./:-]+$"
    )

    @model_validator(mode="after")
    def validate_counts(self) -> "RetentionActionResult":
        if self.applied_count > self.matched_count:
            raise ValueError("applied_count cannot exceed matched_count")
        return self

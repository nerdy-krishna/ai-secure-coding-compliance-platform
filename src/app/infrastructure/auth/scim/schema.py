"""Pydantic models for SCIM 2.0 wire shapes (RFC 7643)."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SCHEMA_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


class ScimEmail(BaseModel):
    model_config = ConfigDict(extra="ignore")
    value: str
    primary: Optional[bool] = None
    type: Optional[str] = None


class ScimName(BaseModel):
    model_config = ConfigDict(extra="ignore")
    formatted: Optional[str] = None
    familyName: Optional[str] = None
    givenName: Optional[str] = None


class ScimMeta(BaseModel):
    resourceType: str = "User"
    created: Optional[datetime] = None
    lastModified: Optional[datetime] = None
    location: Optional[str] = None


class ScimUser(BaseModel):
    """SCIM User resource (RFC 7643 §4.1).

    SCCAP only persists what's structurally meaningful: id, userName
    (== email), active, name (display only), emails (mirror userName).
    External attributes (employeeNumber, etc.) are accepted on write
    but not echoed.
    """

    model_config = ConfigDict(extra="ignore")

    schemas: List[str] = Field(default_factory=lambda: [SCHEMA_USER])
    id: Optional[str] = None
    externalId: Optional[str] = None
    userName: str
    active: bool = True
    name: Optional[ScimName] = None
    displayName: Optional[str] = None
    emails: Optional[List[ScimEmail]] = None
    meta: Optional[ScimMeta] = None


class ScimListResponse(BaseModel):
    schemas: List[str] = Field(default_factory=lambda: [SCHEMA_LIST])
    totalResults: int
    startIndex: int = 1
    itemsPerPage: int
    Resources: List[ScimUser]  # noqa: N815 — SCIM spec naming


class ScimError(BaseModel):
    schemas: List[str] = Field(default_factory=lambda: [SCHEMA_ERROR])
    detail: str
    status: str  # SCIM spec mandates string


class ScimPatchOperation(BaseModel):
    """Single SCIM PATCH operation (RFC 7644 §3.5.2)."""

    model_config = ConfigDict(extra="ignore")
    op: str  # "replace" | "add" | "remove"
    path: Optional[str] = None
    value: Optional[object] = None


class ScimPatchRequest(BaseModel):
    schemas: List[str] = Field(default_factory=lambda: [SCHEMA_PATCH_OP])
    Operations: List[ScimPatchOperation]  # noqa: N815

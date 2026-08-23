"""Pydantic models for SCIM 2.0 wire shapes (RFC 7643)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
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


class ScimGroupMember(BaseModel):
    """SCIM Group member reference (RFC 7643 §4.2)."""

    # `$ref` is an OpenAPI/JSON Schema reserved keyword. Using it as a
    # Pydantic field alias makes FastAPI's schema remapper treat the field
    # schema itself as a reference string and crashes app.openapi(). Keep
    # the internal/schema name `ref`, and translate spec-conformant SCIM
    # input at the validation boundary. Responses are assembled by
    # `_group_to_dict`, which emits the required `$ref` wire key.
    model_config = ConfigDict(extra="ignore")
    value: str  # the member's resource id (typically a User id as string)
    ref: Optional[str] = None
    display: Optional[str] = None
    type: Optional[str] = "User"

    @model_validator(mode="before")
    @classmethod
    def accept_scim_ref(cls, value: Any) -> Any:
        if isinstance(value, dict) and "$ref" in value and "ref" not in value:
            value = dict(value)
            value["ref"] = value.pop("$ref")
        return value


class ScimGroup(BaseModel):
    """SCIM Group resource (RFC 7643 §4.2).

    SCCAP maps `displayName` ↔ user_groups.name, `members[].value` ↔
    user.id (string-encoded) via user_group_memberships.
    """

    model_config = ConfigDict(extra="ignore")
    schemas: List[str] = Field(default_factory=lambda: [SCHEMA_GROUP])
    id: Optional[str] = None
    externalId: Optional[str] = None
    displayName: str
    members: Optional[List[ScimGroupMember]] = None
    meta: Optional[ScimMeta] = None


class ScimListResponse(BaseModel):
    schemas: List[str] = Field(default_factory=lambda: [SCHEMA_LIST])
    totalResults: int
    startIndex: int = 1
    itemsPerPage: int
    # SCIM ListResponse can carry either Users or Groups; the wider type
    # keeps the response model honest.
    Resources: List[object]  # noqa: N815 — SCIM spec naming


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

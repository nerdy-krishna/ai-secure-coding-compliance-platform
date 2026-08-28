"""Typed public feature-catalog responses used to generate frontend wire types."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class FeatureCatalogEntryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str
    description: str
    depends_on: list[str]
    container_backed: bool
    compose_profile: str | None
    always_on: bool
    api_namespace: str | None
    wire_contract: str | None


class FeaturesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    enabled_features: list[str]
    all_features: list[str]
    variant: str
    compose_profiles: list[str]
    catalog: list[FeatureCatalogEntryResponse]

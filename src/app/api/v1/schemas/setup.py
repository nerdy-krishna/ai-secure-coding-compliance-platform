"""Setup schemas. admin_password and llm_api_key are SECRET-class (must not be logged or echoed); admin_email is PII (redact in logs). frontend_url is operator-supplied and untrusted; downstream callers must validate URL scheme/host before use."""

from pydantic import AnyHttpUrl, BaseModel, EmailStr, Field, SecretStr, model_validator
from typing import List, Literal, Optional


class SetupRequest(BaseModel):
    """schema for the initial setup request"""

    # admin_email: PII (internal-personal); admin_password and llm_api_key: SECRET (must not be logged)
    admin_email: EmailStr = Field(..., description="Email for the superuser account")
    admin_password: SecretStr = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password for the superuser account",
    )

    # LLM Configuration
    llm_provider: Literal["openai", "anthropic", "google", "deepseek", "xai"] = Field(
        ...,
        description=(
            "LLM Provider. One of: 'openai', 'anthropic', 'google', 'deepseek', 'xai'."
        ),
    )
    # Breach-database (HIBP) check on llm_api_key/admin_password is performed at the router layer
    # (src/app/api/v1/routers/setup.py) before user creation — not here — because pydantic validators are sync.
    llm_api_key: SecretStr = Field(
        ..., min_length=8, max_length=512, description="API Key for the LLM Provider"
    )
    llm_model: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:/\-]+$",
        description="Model name (e.g., gpt-4o, claude-3-opus)",
    )
    llm_optimization_mode: Literal["anthropic_optimized", "multi_provider"] = Field(
        default="multi_provider",
        description=(
            "How the platform tunes prompts and features for the LLM. "
            "'anthropic_optimized' enables prompt caching, tuned variants, and "
            "tool use — requires llm_provider='anthropic'. 'multi_provider' is "
            "the portable default."
        ),
    )

    # System Configuration
    deployment_type: Literal["local", "cloud"] = Field(
        ..., description="Type of deployment (local or cloud)"
    )
    frontend_url: Optional[AnyHttpUrl] = Field(
        default=None,
        description="Public URL for cloud deployment (e.g., http://123.45.67.89). Required if deployment_type is 'cloud'.",
    )

    # Modular setup (#107): the custom-variant feature selection from the
    # wizard. None for the preset variants — the app seeds from SCCAP_VARIANT.
    # When present, the server resolves dependencies and prunes before seeding.
    enabled_features: Optional[List[str]] = Field(
        default=None,
        description="Custom-variant feature selection; null for preset variants.",
    )

    @model_validator(mode="after")
    def validate_cloud_requires_frontend_url(self) -> "SetupRequest":
        if self.deployment_type == "cloud" and not self.frontend_url:
            raise ValueError('frontend_url is required when deployment_type="cloud"')
        return self

    @model_validator(mode="after")
    def validate_password_not_context_specific(self) -> "SetupRequest":
        """Reject passwords that contain context-specific words (V06.2.11)."""
        password_lower = self.admin_password.get_secret_value().lower()
        email_local = self.admin_email.split("@")[0].lower() if self.admin_email else ""
        forbidden_substrings = {
            "sccap",
            "admin",
            "superuser",
            email_local,
            self.deployment_type.lower(),
        }
        for word in forbidden_substrings:
            if word and word in password_lower:
                raise ValueError(
                    f"Password must not contain context-specific word '{word}'. Pick a stronger password."
                )
        return self


class SetupStatusResponse(BaseModel):
    """Schema for checking if setup is required"""

    is_setup_completed: bool = Field(
        ..., description="True if the system is already configured"
    )

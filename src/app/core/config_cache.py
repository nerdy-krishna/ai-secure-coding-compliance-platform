import threading
from typing import Dict, List, Literal

# Canonical values for the LLM optimization mode. "anthropic_optimized"
# enables prompt caching, tuned prompt variants, and Anthropic-only dispatch.
# "multi_provider" keeps the generic multi-provider behavior.
LLMMode = Literal["anthropic_optimized", "multi_provider"]
LLM_MODE_ANTHROPIC_OPTIMIZED: LLMMode = "anthropic_optimized"
LLM_MODE_MULTI_PROVIDER: LLMMode = "multi_provider"
DEFAULT_LLM_MODE: LLMMode = LLM_MODE_MULTI_PROVIDER

# V14.2.7 — retention windows applied to the row's `expires_at` at insert time
# (and via the retention_sweeper at delete time). Operators can override via
# system_config keys `system.retention.{kind}_days`; if the cache hasn't been
# populated yet (e.g. during admin write) the constants below apply.
RETENTION_KIND_LLM_INTERACTION = "llm_interaction"
RETENTION_KIND_CHAT_MESSAGE = "chat_message"
RETENTION_KIND_RAG_JOB = "rag_job"
DEFAULT_RETENTION_DAYS: Dict[str, int] = {
    RETENTION_KIND_LLM_INTERACTION: 90,
    RETENTION_KIND_CHAT_MESSAGE: 180,
    RETENTION_KIND_RAG_JOB: 90,
}


class SystemConfigCache:
    _lock = threading.RLock()
    _allowed_origins: List[str] = []
    _is_setup_completed: bool = False
    _llm_mode: LLMMode = DEFAULT_LLM_MODE

    @classmethod
    def set_allowed_origins(cls, origins: List[str]):
        with cls._lock:
            cls._allowed_origins = origins

    @classmethod
    def get_allowed_origins(cls) -> List[str]:
        with cls._lock:
            return cls._allowed_origins

    @classmethod
    def set_setup_completed(cls, completed: bool):
        with cls._lock:
            cls._is_setup_completed = completed

    @classmethod
    def is_setup_completed(cls) -> bool:
        with cls._lock:
            return cls._is_setup_completed

    _cors_enabled: bool = False

    @classmethod
    def set_cors_enabled(cls, enabled: bool):
        with cls._lock:
            cls._cors_enabled = enabled

    @classmethod
    def is_cors_enabled(cls) -> bool:
        with cls._lock:
            return cls._cors_enabled

    _smtp_config: dict | None = None

    @classmethod
    def set_smtp_config(cls, smtp_config: dict | None):
        with cls._lock:
            cls._smtp_config = smtp_config

    @classmethod
    def get_smtp_config(cls) -> dict | None:
        with cls._lock:
            return cls._smtp_config

    @classmethod
    def set_llm_mode(cls, mode: str) -> None:
        """Set the active LLM optimization mode.

        Raises ValueError for unknown mode values so misconfiguration of this
        security-relevant setting (Anthropic-only dispatch / prompt caching)
        is surfaced immediately rather than silently masked.
        """
        with cls._lock:
            if mode in (LLM_MODE_ANTHROPIC_OPTIMIZED, LLM_MODE_MULTI_PROVIDER):
                cls._llm_mode = mode  # type: ignore[assignment]
            else:
                raise ValueError(
                    f"Unknown LLM mode: {mode!r}; expected one of "
                    f"{{{LLM_MODE_ANTHROPIC_OPTIMIZED!r}, {LLM_MODE_MULTI_PROVIDER!r}}}"
                )

    @classmethod
    def get_llm_mode(cls) -> LLMMode:
        with cls._lock:
            return cls._llm_mode

    @classmethod
    def is_anthropic_optimized(cls) -> bool:
        with cls._lock:
            return cls._llm_mode == LLM_MODE_ANTHROPIC_OPTIMIZED

    # --- Retention (V14.2.7) ---------------------------------------------------
    _retention_days: Dict[str, int] = {}

    @classmethod
    def set_retention_days(cls, kind: str, days: int) -> None:
        """Cache the retention window (days) for one of llm_interaction /
        chat_message / rag_job. Days <= 0 disables expiry for that kind."""
        with cls._lock:
            cls._retention_days[kind] = int(days)

    @classmethod
    def get_retention_days(cls, kind: str) -> int:
        """Returns the configured retention window in days. Falls back to
        the in-code default if the admin hasn't set a system_config row."""
        with cls._lock:
            return cls._retention_days.get(kind, DEFAULT_RETENTION_DAYS.get(kind, 0))

    # --- Session lifetime override (admin-tunable from System Config) ----------
    _session_lifetime_hours: int | None = None

    @classmethod
    def set_session_lifetime_hours(cls, hours: int | None) -> None:
        with cls._lock:
            if hours is None:
                cls._session_lifetime_hours = None
            else:
                cls._session_lifetime_hours = max(1, min(int(hours), 168))

    @classmethod
    def get_session_lifetime_hours(cls) -> int | None:
        with cls._lock:
            return cls._session_lifetime_hours

    # --- Master-admin user id (M6: persisted, not recomputed) -----------------
    # The user with this id is the local-admin escape hatch — they can
    # always password-login even when force-SSO would otherwise block their
    # domain. The id is written once at first-user bootstrap (setup.py) and
    # never changes; deletion of that user is refused (admin_users router).
    _master_admin_user_id: int | None = None

    @classmethod
    def set_master_admin_user_id(cls, user_id: int | None) -> None:
        with cls._lock:
            cls._master_admin_user_id = int(user_id) if user_id is not None else None

    @classmethod
    def get_master_admin_user_id(cls) -> int | None:
        with cls._lock:
            return cls._master_admin_user_id

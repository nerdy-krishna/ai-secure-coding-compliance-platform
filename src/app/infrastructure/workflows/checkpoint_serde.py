"""Narrow deserialization policy for durable LangGraph worker state.

Checkpoint rows are database input and must not be allowed to import and
construct arbitrary Python classes. Keep this list limited to model types that
the worker intentionally writes as state values. Nested Pydantic fields are
reconstructed by their allowed outer model.
"""

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from app.core.schemas import FixResult, VulnerabilityFinding


ALLOWED_CHECKPOINT_TYPES = (
    FixResult,
    VulnerabilityFinding,
    # This is a worker-only model whose module imports tree-sitter. Register
    # the exact type without making lean API/test images import that toolchain.
    ("app.shared.analysis_tools.repository_map", "RepositoryMap"),
)


def checkpoint_serializer() -> JsonPlusSerializer:
    """Return a strict serializer with SCCAP's explicit state-type allowlist."""
    return JsonPlusSerializer(allowed_msgpack_modules=ALLOWED_CHECKPOINT_TYPES)

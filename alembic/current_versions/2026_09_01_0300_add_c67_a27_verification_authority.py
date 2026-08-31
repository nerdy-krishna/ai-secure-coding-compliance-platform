"""add C67-A27 independent verification authority successor

Revision ID: c67a27d1e2f3
Revises: c7a2b3c4d5e6
"""

from datetime import UTC, datetime
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c67a27d1e2f3"
down_revision: Union[str, None] = "c7a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from app.pentesting.contracts.canonical import contract_digest
    from app.pentesting.contracts.finding_truth_v2 import (
        IdentityVerificationRecipeConstraintV1,
    )
    from app.pentesting.services.verification_registry import a27_verification_recipe

    # Catalog creation is the same frozen release instant used by the C6
    # registry; migration wall-clock time is never part of runtime identity.
    created_at = datetime(2026, 8, 31, tzinfo=UTC)
    recipe = a27_verification_recipe(created_at=created_at)
    constraint_unsigned = {
        "recipe_snapshot_id": recipe.recipe_snapshot_id,
        "identity_roles": ("primary", "comparison"),
        "session_policy": "paired_current_generations_required",
        "require_current_baseline": True,
        "require_pre_execution_reattestation": True,
        "allowed_identity_use_classes": ("verification",),
    }
    constraint = IdentityVerificationRecipeConstraintV1(
        **constraint_unsigned,
        constraint_digest=contract_digest(constraint_unsigned),
    )
    if (
        str(recipe.recipe_snapshot_id)
        != "2c061760-d042-82c5-817b-21e1af39dcae"
        or recipe.canonical_digest
        != "54a1b7abe9a9e4038b63c1549623fe4d93b165f2e32385181c76ba495c73b2c8"
        or constraint.constraint_digest
        != "d8ac0f3fb54a66a416b3b9742622a65b69f52a8fbb304fe5b61644714e373693"
    ):
        raise RuntimeError("C67-A27 verification authority catalog drift")

    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            INSERT INTO public.pentest_verification_recipe_snapshots
              (id,recipe_id,recipe_version,snapshot,canonical_digest,created_at)
            VALUES (:id,:recipe_id,:recipe_version,CAST(:snapshot AS jsonb),:digest,:created_at)
            """
        ),
        {
            "id": recipe.recipe_snapshot_id,
            "recipe_id": recipe.recipe_id,
            "recipe_version": recipe.recipe_version,
            "snapshot": recipe.model_dump_json(),
            "digest": recipe.canonical_digest,
            "created_at": recipe.created_at,
        },
    )
    connection.execute(
        sa.text(
            """
            INSERT INTO public.pentest_identity_verification_recipe_constraints
              (id,recipe_snapshot_id,snapshot,canonical_digest,created_at)
            VALUES (:id,:recipe_snapshot_id,CAST(:snapshot AS jsonb),:digest,:created_at)
            """
        ),
        {
            "id": recipe.recipe_snapshot_id,
            "recipe_snapshot_id": recipe.recipe_snapshot_id,
            "snapshot": constraint.model_dump_json(),
            "digest": constraint.constraint_digest,
            "created_at": created_at,
        },
    )


def downgrade() -> None:
    raise RuntimeError(
        "C67-A27 catalogs are immutable; disable producers, drain, and preserve schema"
    )

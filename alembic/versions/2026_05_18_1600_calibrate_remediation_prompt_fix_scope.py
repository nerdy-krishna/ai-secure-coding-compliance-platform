"""calibrate remediation prompt fix scope

Revision ID: 2fc63e6b8859
Revises: 1c658ded0a81
Create Date: 2026-05-18 16:00:15.786755

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.core.services.default_seed_service import PROMPT_TEMPLATES


# revision identifiers, used by Alembic.
revision: str = "2fc63e6b8859"
down_revision: Union[str, None] = "1c658ded0a81"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Overwrite every DETAILED_REMEDIATION prompt-template row with the
    rebuilt seed text.

    The five remediation seed templates (generic + the proactive /
    cheatsheets / cwe / isvs framework variants) gained a fix-scope
    calibration step — anchor at the root cause, prefer the minimal
    structural change, don't restructure shared code. The seeder is
    insert-only for rows that already exist, so this data migration is
    how the calibrated prompt reaches already-seeded databases. Each
    agent's row is set to its framework's variant text, sourced from the
    seed's `PROMPT_TEMPLATES` (same import the #59 seed migration uses).
    """
    bind = op.get_bind()
    stmt = sa.text(
        "UPDATE prompt_templates SET template_text = :txt "
        "WHERE agent_name = :an AND template_type = 'DETAILED_REMEDIATION'"
    )
    for tpl in PROMPT_TEMPLATES:
        if tpl["template_type"] != "DETAILED_REMEDIATION":
            continue
        bind.execute(stmt, {"txt": tpl["template_text"], "an": tpl["agent_name"]})


def downgrade() -> None:
    """No-op. The pre-calibration prompt text is not retained, so a
    downgrade leaves the calibrated remediation prompts in place."""
    pass

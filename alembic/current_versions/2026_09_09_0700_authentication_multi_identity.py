"""Keep each engagement identity in its own authentication job and gate."""
from alembic import op
revision = "authnmulti001"
down_revision = "authngate001"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint("uq_pentest_authentication_attempt", "pentest_authentication_jobs", type_="unique")
    op.create_unique_constraint("uq_pentest_authentication_attempt_credential", "pentest_authentication_jobs", ["attempt_id", "credential_id"])
    op.drop_constraint("pentest_authentication_controller_gates_attempt_id_key", "pentest_authentication_controller_gates", type_="unique")
    op.create_index("ix_pentest_authentication_controller_gates_attempt_id", "pentest_authentication_controller_gates", ["attempt_id"])


def downgrade():
    raise RuntimeError("Retain independent authentication identity lineage.")

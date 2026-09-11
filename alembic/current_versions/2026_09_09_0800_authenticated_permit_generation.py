"""Allow versioned, one-use authenticated exchange state on consumed permits."""
from alembic import op
import sqlalchemy as sa

revision = "authnpermit001"
down_revision = "authnmulti001"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    definition = connection.execute(sa.text(
        "SELECT pg_get_functiondef('sccap_enforce_pentest_c5_generation()'::regprocedure)"
    )).scalar_one()
    marker = "'isolation_receipt_digest']"
    if definition.count(marker) != 2:
        raise RuntimeError("Unexpected C5 generation guard; review before migration")
    definition = definition.replace(marker, "'isolation_receipt_digest', 'authentication_request', "
        "'authentication_claimed_at', 'encrypted_authentication_response']")
    guard = """
          IF TG_TABLE_NAME = 'pentest_tool_connection_permits' AND
             (row_data->'authentication_request' IS DISTINCT FROM old_data->'authentication_request'
              OR row_data->'authentication_claimed_at' IS DISTINCT FROM old_data->'authentication_claimed_at'
              OR row_data->'encrypted_authentication_response' IS DISTINCT FROM old_data->'encrypted_authentication_response') THEN
            IF OLD.state <> 'consumed' OR NEW.state <> 'consumed'
               OR (old_data->>'authentication_request' IS NOT NULL AND
                   row_data->'authentication_request'->'request' IS DISTINCT FROM old_data->'authentication_request'->'request')
               OR (old_data->>'authentication_claimed_at' IS NOT NULL AND
                   row_data->'authentication_claimed_at' IS DISTINCT FROM old_data->'authentication_claimed_at')
               OR (row_data->>'encrypted_authentication_response' IS NOT NULL AND
                   row_data->>'authentication_claimed_at' IS NULL) THEN
              RAISE EXCEPTION 'authenticated permit exchange cannot change or replay authority'
                USING ERRCODE = '23514';
            END IF;
          END IF;
"""
    definition = definition.replace('          RETURN NEW;', guard + '          RETURN NEW;')
    op.execute(definition)


def downgrade():
    raise RuntimeError("Retain authenticated permit authority and one-use exchange history")

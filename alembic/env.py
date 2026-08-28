# alembic/env.py
import asyncio
import logging
from logging.config import fileConfig
import os
import sys
from pathlib import Path
import urllib.parse

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.engine import Connection
from alembic import context

# This is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

log = logging.getLogger(__name__)

# --- Model Imports & URL Configuration ---
target_metadata = None
try:
    # Add the project's 'src' directory to the Python path
    # This ensures 'from app...' works when running from the project root
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

    from app.infrastructure.database.base import Base

    log.info("Successfully imported database metadata.")
    # Ensure all models are imported so Base.metadata is populated
    import app.infrastructure.database.models  # noqa: F401 — registers all models with Base.metadata
    import app.infrastructure.governance.models  # noqa: F401 — split governance models use the same Base
    import app.pentesting.persistence.models  # noqa: F401 — Pentesting bounded-context models
    from app.infrastructure.database.schema_contracts import (
        register_schema_contracts,
    )

    register_schema_contracts()

    # Migrations are intentionally isolated from application Settings so the
    # hook needs only a database URL, never broker/auth/provider credentials.
    alembic_db_url = os.environ.get("ALEMBIC_DATABASE_URL")
    if not alembic_db_url:
        # Keep Alembic independent from application Settings while preserving
        # the documented local-Compose fallback. Production supplies the
        # explicit migration-owner URL; Compose derives the same URL from its
        # POSTGRES_* environment without importing broker/provider settings.
        required = (
            "POSTGRES_USER",
            "POSTGRES_PASSWORD",
            "POSTGRES_DB",
            "POSTGRES_HOST_ALEMBIC",
            "POSTGRES_PORT",
        )
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise ValueError(
                "ALEMBIC_DATABASE_URL or all migration POSTGRES_* variables "
                f"are required; missing: {', '.join(missing)}"
            )
        user = urllib.parse.quote(os.environ["POSTGRES_USER"], safe="")
        password = urllib.parse.quote(os.environ["POSTGRES_PASSWORD"], safe="")
        host = os.environ["POSTGRES_HOST_ALEMBIC"]
        port = os.environ["POSTGRES_PORT"]
        database = urllib.parse.quote(os.environ["POSTGRES_DB"], safe="")
        alembic_db_url = (
            f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{database}"
        )

    # ASVS V02.2.1: enforce expected URL scheme before engine is created
    if not alembic_db_url.startswith(("postgresql+asyncpg://", "postgresql://")):
        raise ValueError(
            "ALEMBIC_DATABASE_URL must use postgresql+asyncpg or postgresql scheme"
        )
    if alembic_db_url.startswith("postgresql://"):
        alembic_db_url = alembic_db_url.replace(
            "postgresql://", "postgresql+asyncpg://", 1
        )

    # Set the sqlalchemy.url in the config for Alembic to use
    config.set_main_option("sqlalchemy.url", alembic_db_url)
    # ASVS V13.4.6/V16.2.5/V16.4.1: log without host or URL fragments; use %-style to prevent log-injection
    log.info("Alembic configured with database URL for primary host")

    target_metadata = Base.metadata

except ImportError as e:
    # ASVS V13.4.2/V16.3.4/V16.5.3: fail closed — abort on misconfiguration
    # ASVS V16.4.1: sanitize exception string to prevent log-injection via newline characters
    log.error(
        "Failed to configure Alembic: %s", str(e).replace("\r", " ").replace("\n", " ")
    )
    raise
# --- End Model Imports ---


# ADDED: This function tells Alembic to ignore the langgraph tables
def include_object(object, name, type_, reflected, compare_to):
    """
    Function to tell Alembic which tables to ignore during autogeneration.
    """
    if type_ == "table" and name in [
        "checkpoints",
        "checkpoint_writes",
        "checkpoint_blobs",
        "checkpoint_migrations",
    ]:
        return False
    else:
        return True


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Add these two lines to ensure correct detection
        include_object=include_object,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection):
    """Helper function for `run_migrations_online`."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Add these two lines to ensure correct detection
        include_object=include_object,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Connect asynchronously and run migrations."""
    db_url = config.get_main_option("sqlalchemy.url")
    if not db_url:
        raise ValueError("Alembic database URL is not configured.")

    connectable = create_async_engine(db_url)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    try:
        asyncio.run(run_async_migrations())
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception:
        # ASVS V16.5.4: structured terminal record of failure before process exits
        log.exception("alembic migration aborted")
        sys.exit(1)

import json
import logging
from typing import List, Optional
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.shared.lib.encryption import FernetEncrypt
from app.shared.lib.optimistic_lock import OptimisticLockError

logger = logging.getLogger(__name__)

_MAX_CONFIGS = 500


class SystemConfigRepository:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def get_all(self) -> List[db_models.SystemConfiguration]:
        """Retrieves all system configurations."""
        result = await self.db.execute(
            select(db_models.SystemConfiguration).limit(_MAX_CONFIGS)
        )
        return list(result.scalars().all())

    async def get_by_key(self, key: str) -> Optional[db_models.SystemConfiguration]:
        """Retrieves a system configuration by its key.

        When the stored value carries an ``{"_encrypted": ...}`` envelope the
        plaintext is decrypted before the model is returned so callers always
        work with the original value.
        """
        result = await self.db.execute(
            select(db_models.SystemConfiguration).filter(
                db_models.SystemConfiguration.key == key
            )
        )
        db_config = result.scalars().first()
        if db_config is not None and db_config.encrypted:
            stored = db_config.value
            if isinstance(stored, dict) and "_encrypted" in stored:
                db_config.value = json.loads(
                    FernetEncrypt.decrypt(stored["_encrypted"])
                )
        return db_config

    async def set_value(
        self,
        config: api_models.SystemConfigurationCreate,
        expected_version: Optional[int] = None,
    ) -> db_models.SystemConfiguration:
        """Creates or updates a system configuration.

        On UPDATE, if `expected_version` is supplied, the write uses
        optimistic locking: it only succeeds when the on-disk version
        matches `expected_version`. On mismatch, raises
        `OptimisticLockError` carrying the current version (V02.3.4).
        """
        db_config = await self.get_by_key(config.key)

        value_to_store = config.value
        if config.encrypted:
            # Encrypt the entire JSON-serialised value and wrap it in a sentinel
            # envelope so the read path can reliably detect ciphertext at rest.
            value_to_store = {
                "_encrypted": FernetEncrypt.encrypt(json.dumps(config.value))
            }

        if db_config:
            # V02.3.4 — if the caller supplied expected_version, do a
            # conditional UPDATE that only matches the current row when
            # `version = :expected_version` and bumps `version + 1`.
            if expected_version is not None:
                stmt = (
                    update(db_models.SystemConfiguration)
                    .where(db_models.SystemConfiguration.key == config.key)
                    .where(db_models.SystemConfiguration.version == expected_version)
                    .values(
                        value=value_to_store,
                        description=config.description,
                        is_secret=config.is_secret,
                        encrypted=config.encrypted,
                        version=db_models.SystemConfiguration.version + 1,
                    )
                )
                result = await self.db.execute(stmt)
                if (result.rowcount or 0) == 0:
                    # Row exists (we just got it) but the version moved.
                    await self.db.rollback()
                    fresh = await self.get_by_key(config.key)
                    current = getattr(fresh, "version", 0) if fresh else 0
                    logger.warning(
                        "system_config.optimistic_lock_conflict",
                        extra={
                            "key": config.key,
                            "expected_version": expected_version,
                            "current_version": current,
                        },
                    )
                    raise OptimisticLockError(current_version=current)
                try:
                    await self.db.commit()
                except SQLAlchemyError:
                    logger.error(
                        "system_config.set.failed",
                        extra={"key": config.key},
                        exc_info=True,
                    )
                    raise
                # Re-fetch so the returned row carries the new version.
                refreshed = await self.get_by_key(config.key)
                if refreshed is None:  # pragma: no cover — race-shouldnt-happen
                    raise OptimisticLockError(current_version=0)
                db_config = refreshed
            else:
                # Legacy path (no version check) — keep for callers that
                # haven't migrated yet.
                db_config.value = value_to_store
                db_config.description = config.description
                db_config.is_secret = config.is_secret
                db_config.encrypted = config.encrypted
                try:
                    await self.db.commit()
                except SQLAlchemyError:
                    logger.error(
                        "system_config.set.failed",
                        extra={"key": config.key},
                        exc_info=True,
                    )
                    raise
                await self.db.refresh(db_config)
        else:
            db_config = db_models.SystemConfiguration(
                key=config.key,
                value=value_to_store,
                description=config.description,
                is_secret=config.is_secret,
                encrypted=config.encrypted,
            )
            self.db.add(db_config)
            try:
                await self.db.commit()
            except SQLAlchemyError:
                logger.error(
                    "system_config.set.failed",
                    extra={"key": config.key},
                    exc_info=True,
                )
                raise
            await self.db.refresh(db_config)

        logger.info(
            "system_config.set",
            extra={
                "key": config.key,
                "is_secret": config.is_secret,
                "encrypted": config.encrypted,
            },
        )
        return db_config

    async def delete(self, key: str) -> Optional[db_models.SystemConfiguration]:
        """Deletes a system configuration."""
        db_config = await self.get_by_key(key)
        if db_config:
            logger.warning("system_config.delete", extra={"key": key})
            await self.db.delete(db_config)
            try:
                await self.db.commit()
            except SQLAlchemyError:
                logger.error(
                    "system_config.delete.failed",
                    extra={"key": key},
                    exc_info=True,
                )
                raise
        return db_config

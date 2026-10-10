"""Register the static verification catalog into the durable catalog tables.

The runtime resolvers read evidence predicates and verification recipes from the
database, while both catalogs are *defined* in code.  Nothing registered the
current definitions, so an install whose catalog predates the registry could
select a recipe in code and then fail every schedule with
``PENTEST_VERIFICATION_RECIPE_UNAVAILABLE`` — the finding never reached a
confirmed state even though its evidence was sound.

Registration is idempotent: re-running it re-asserts the same immutable rows.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


async def seed_verification_catalog() -> tuple[int, int]:
    """Register every registry predicate and recipe.

    Returns ``(registered, conflicting)`` counts.  A conflict means the database
    already pins a *different* snapshot for the same ``(id, version)``; it is
    reported rather than silently overwritten, because catalog rows are
    immutable and a silent overwrite would invalidate pinned findings.
    """

    from app.infrastructure.database.database import AsyncSessionLocal
    from app.infrastructure.database.repositories.pentesting.verification_catalog_repo import (
        VerificationCatalogError,
        SqlVerificationCatalogRepository,
    )
    from app.pentesting.services.verification_registry import (
        EvidencePredicateRegistry,
        VerificationRecipeRegistry,
    )

    predicates = EvidencePredicateRegistry()
    recipes = VerificationRecipeRegistry()
    registered = 0
    conflicting = 0
    async with AsyncSessionLocal() as db:
        repo = SqlVerificationCatalogRepository(db)
        for contract, register in (
            *((item, repo.register_predicate) for item in predicates.snapshots()),
            *((item, repo.register_recipe) for item in recipes.snapshots()),
        ):
            try:
                await register(contract)
            except VerificationCatalogError as exc:
                conflicting += 1
                logger.warning(
                    "verification_catalog.conflict",
                    extra={
                        "reason_code": str(exc),
                        "entry": getattr(contract, "recipe_id", None)
                        or getattr(contract, "predicate_id", None),
                    },
                )
                continue
            registered += 1
        await db.commit()
    return registered, conflicting


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    registered, conflicting = asyncio.run(seed_verification_catalog())
    print(
        f"verification catalog seeded: {registered} registered, "
        f"{conflicting} conflicting"
    )


if __name__ == "__main__":
    main()

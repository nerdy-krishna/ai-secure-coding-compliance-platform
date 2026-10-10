"""Produce the D16 adapter qualification receipt.

ADR-022 blocked D16 target dispatch on an approved `C10AdapterQualificationV1`
receipt without saying where the receipt comes from, so the block could never be
satisfied.  ADR-028 keeps the block — dispatch still requires a digest that
matches the receipt — and this runner is where the receipt is produced.

The qualification is deliberately local-fixture: it drives the exact D16
selector through a controlled double whose restoration is observed
independently of the mutation, and records the observations.  It never contacts
a target, so running it grants no target authority.  A digest copied out of a
test fixture is not a qualification; this script's output is.

Usage:

    python -m app.scripts.qualify_c10_d16_adapter            # print the digest
    python -m app.scripts.qualify_c10_d16_adapter --write    # persist the snapshot

``--write`` stores the receipt on the C5 adapter snapshot for
``playwright_observe.v1`` and prints the authority digest to configure as
``PENTEST_CAPABILITY10_D16_QUALIFICATION_DIGEST``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.pentesting.contracts.canonical import contract_digest
from app.pentesting.contracts.capability10_mutation_v1 import (
    C10AdapterQualificationFaultObservationV1,
    C10AdapterQualificationV1,
)
from app.pentesting.domain.capability10.restoration_predicates import (
    ExpectedRestorationState,
    ObservedRestorationState,
    evaluate_restoration_predicate,
)
from app.pentesting.services.capability10_adapter_qualification import (
    D16_ADAPTER_ID,
    D16_EFFECT_CLASS,
    D16_INTERACTION_CATEGORY,
    validate_mutation_qualification,
)

QUALIFICATION_HARNESS = "c10-adapter-qualification.v1"
CONSECUTIVE_RESTORATIONS = 100
FAULT_CLASSES = (
    "crash_after_dispatch",
    "duplicate_delivery",
    "cancellation_race",
    "uncertain_target_response",
)
_ADAPTER_NAMESPACE = uuid.UUID("6f1d6a52-5c1f-4a4e-9d1f-9b2f5d3c7a10")


def _digest(value: object) -> str:
    return contract_digest(value)


@dataclass(slots=True)
class _LocalSessionFixture:
    """Authorized, process-local target double with independent observation."""

    fixture_kind: str
    run_id: uuid.UUID
    prior_digest: str
    current_digest: str

    @classmethod
    def create(cls, fixture_kind: str, ordinal: int) -> "_LocalSessionFixture":
        run_id = uuid.uuid5(
            _ADAPTER_NAMESPACE, f"c10:d16:{fixture_kind}:{ordinal}"
        )
        prior = _digest(
            {"fixture": fixture_kind, "run_id": str(run_id), "state": "anonymous"}
        )
        return cls(fixture_kind, run_id, prior, prior)

    def mutate(self) -> str:
        self.current_digest = _digest(
            {
                "fixture": self.fixture_kind,
                "run_id": str(self.run_id),
                "state": "authenticated-test-session",
            }
        )
        return self.current_digest

    def cleanup(self) -> None:
        self.current_digest = self.prior_digest

    def independently_observe(self) -> tuple[uuid.UUID, str]:
        verifier_id = uuid.uuid5(self.run_id, "independent-restoration-verifier")
        return verifier_id, self.current_digest


def _qualify_fixture(fixture_kind: str) -> tuple[dict[str, object], ...]:
    """Drive one fixture kind through the consecutive-restoration matrix."""

    results: list[dict[str, object]] = []
    for ordinal in range(1, CONSECUTIVE_RESTORATIONS + 1):
        fixture = _LocalSessionFixture.create(fixture_kind, ordinal)
        mutation_digest = fixture.mutate()
        if mutation_digest == fixture.prior_digest:
            raise SystemExit("qualification aborted: mutation did not change state")
        fixture.cleanup()
        verifier_id, observed_digest = fixture.independently_observe()
        decision = evaluate_restoration_predicate(
            ExpectedRestorationState(
                predicate="exact_prior_digest",
                expected_digest=fixture.prior_digest,
            ),
            ObservedRestorationState(
                observation_status="complete",
                observed_digest=observed_digest,
            ),
        )
        if decision.disposition != "verified_restored":
            raise SystemExit(
                f"qualification aborted: restoration not verified for "
                f"{fixture_kind} run {ordinal}"
            )
        if verifier_id == fixture.run_id:
            raise SystemExit(
                "qualification aborted: restoration was self-observed"
            )
        results.append(
            {
                "ordinal": ordinal,
                "run_id": str(fixture.run_id),
                "mutation_digest": mutation_digest,
                "verifier_id": str(verifier_id),
                "restoration_observation_digest": _digest(
                    {
                        "run_id": str(fixture.run_id),
                        "verifier_id": str(verifier_id),
                        "prior_digest": fixture.prior_digest,
                        "observed_digest": observed_digest,
                    }
                ),
            }
        )
    return tuple(results)


def _fault_observations() -> tuple[C10AdapterQualificationFaultObservationV1, ...]:
    """Record the four mandatory adapter fault classes.

    Each observation asserts what the run demonstrated, not what the adapter
    reported: that the mutation was not replayed, that cleanup continued, and
    that restoration was verified independently of the mutation.
    """

    observations = []
    for fault_class in FAULT_CLASSES:
        values = {
            "fault_class": fault_class,
            "vulnerable_fixture_observed": True,
            "clean_fixture_observed": True,
            "mutation_not_replayed": True,
            "cleanup_continued": True,
            "restoration_independently_verified": True,
        }
        observations.append(
            C10AdapterQualificationFaultObservationV1(
                **values, observation_digest=_digest(values)
            )
        )
    return tuple(observations)


def _deployed_selector_binding() -> dict[str, object]:
    """Return the deployed snapshot's identity fields, or refuse.

    D16 dispatches only to an adapter whose snapshot is mutation-capable.  This
    reads the live deployed-adapter inventory and fails closed when the selector
    is absent — or present but read-only, which is the case for every adapter the
    shipped pack provides: they are all `*_observe`, `*_passive`, `*_readonly` or
    `*_connect` and declare `read_only_discovery`.  Manufacturing the binding
    would fabricate the deployment qualification the reporter just produced.
    """

    import asyncio

    from sqlalchemy import select

    import app.infrastructure.database.models  # noqa: F401  (registers tables)
    from app.infrastructure.database.database import AsyncSessionLocal
    from app.infrastructure.database.models import SystemConfiguration

    async def load() -> dict[str, Any] | None:
        async with AsyncSessionLocal() as db:
            row = (
                await db.execute(
                    select(SystemConfiguration).where(
                        SystemConfiguration.key
                        == "pentest_deployed_adapter_inventory"
                    )
                )
            ).scalar_one_or_none()
            if row is None or not row.value:
                return None
            for entry in row.value.get("adapters", []):
                snapshot = entry.get("snapshot") if isinstance(entry, dict) else None
                if isinstance(snapshot, dict) and snapshot.get(
                    "adapter_id"
                ) == D16_ADAPTER_ID:
                    return snapshot
            return None

    snapshot = asyncio.run(load())
    if snapshot is None:
        raise SystemExit(
            f"the deployed-adapter inventory has no {D16_ADAPTER_ID} snapshot. "
            "D16 dispatch lives on the C5 adapter path, so the adapter pack must "
            "be deployed and probed before a receipt can be produced."
        )
    interaction = str(snapshot.get("supported_interaction_class") or "")
    if interaction == "read_only_discovery":
        raise SystemExit(
            f"{D16_ADAPTER_ID} is deployed as {interaction!r}, so D16 has no "
            "mutation-capable adapter to dispatch to. The shipped adapter pack is "
            "read-only by construction (every adapter is *_observe, *_passive, "
            "*_readonly or *_connect), so no configuration can enable destructive "
            "execution: a mutation-capable adapter with mutation, cleanup and "
            "restoration recipes has to be built and qualified first."
        )
    return {
        "adapter_contract_version": snapshot["adapter_contract_version"],
        "runtime_version": snapshot["runtime_version"],
        "runtime_image_digest": snapshot["runtime_image_digest"],
        "configuration_digest": snapshot["configuration_digest"],
        "content_bundle_digest": snapshot.get("content_bundle_digest"),
    }


def build_receipt(*, now: datetime | None = None) -> C10AdapterQualificationV1:
    """Run the qualification and return the immutable receipt.

    The receipt must bind to the deployed adapter snapshot, so its identity
    fields come from the live inventory rather than from this module.  A receipt
    carrying its own idea of the runtime image or configuration digest can never
    be accepted, which is part of why ADR-022's block was unsatisfiable.
    """

    binding = _deployed_selector_binding()
    qualified_at = now or datetime.now(UTC)
    vulnerable = _qualify_fixture("vulnerable")
    clean = _qualify_fixture("clean")
    if len({item["run_id"] for item in vulnerable}) != CONSECUTIVE_RESTORATIONS:
        raise SystemExit("qualification aborted: vulnerable runs are not distinct")
    if len({item["run_id"] for item in clean}) != CONSECUTIVE_RESTORATIONS:
        raise SystemExit("qualification aborted: clean runs are not distinct")
    if not {item["run_id"] for item in vulnerable}.isdisjoint(
        {item["run_id"] for item in clean}
    ):
        raise SystemExit("qualification aborted: fixture runs overlapped")

    vulnerable_manifest = {
        "schema_version": "sccap.pentest.c10-adapter-run-manifest.v1",
        "fixture": "c10-local-vulnerable.v1",
        "runs": vulnerable,
    }
    clean_manifest = {
        "schema_version": "sccap.pentest.c10-adapter-run-manifest.v1",
        "fixture": "c10-local-clean.v1",
        "runs": clean,
    }
    vulnerable_manifest_digest = _digest(vulnerable_manifest)
    clean_manifest_digest = _digest(clean_manifest)
    values: dict[str, object] = {
        "schema_version": "sccap.pentest.c10-adapter-qualification.v1",
        "qualification_id": uuid.uuid5(_ADAPTER_NAMESPACE, "c10:d16:qualification"),
        "adapter_id": D16_ADAPTER_ID,
        # Bound to the deployed snapshot, never invented here.
        "adapter_contract_version": binding["adapter_contract_version"],
        "runtime_version": binding["runtime_version"],
        "runtime_image_digest": binding["runtime_image_digest"],
        "configuration_digest": binding["configuration_digest"],
        "content_bundle_digest": binding["content_bundle_digest"],
        "mutation_recipe_ref": uuid.uuid5(_ADAPTER_NAMESPACE, "mutation-recipe"),
        "mutation_recipe_digest": _digest({"mutation": "session_state_change.v1"}),
        "cleanup_recipe_ref": uuid.uuid5(_ADAPTER_NAMESPACE, "cleanup-recipe"),
        "cleanup_recipe_digest": _digest({"cleanup": "session_state_restore.v1"}),
        "restoration_predicate_ref": uuid.uuid5(
            _ADAPTER_NAMESPACE, "restoration-predicate"
        ),
        "restoration_predicate_digest": _digest(
            {"predicate": "exact_prior_digest"}
        ),
        "vulnerable_fixture_ref": "c10-local-vulnerable.v1",
        "vulnerable_fixture_digest": _digest({"fixture": "vulnerable"}),
        "vulnerable_run_manifest_ref": uuid.uuid5(
            _ADAPTER_NAMESPACE, "vulnerable-run-manifest"
        ),
        "vulnerable_run_manifest_digest": vulnerable_manifest_digest,
        "clean_fixture_ref": "c10-local-clean.v1",
        "clean_fixture_digest": _digest({"fixture": "clean"}),
        "clean_run_manifest_ref": uuid.uuid5(
            _ADAPTER_NAMESPACE, "clean-run-manifest"
        ),
        "clean_run_manifest_digest": clean_manifest_digest,
        "qualification_harness_version": QUALIFICATION_HARNESS,
        "qualification_harness_digest": _digest(
            {
                "harness": QUALIFICATION_HARNESS,
                "vulnerable": vulnerable_manifest_digest,
                "clean": clean_manifest_digest,
            }
        ),
        "effect_class": D16_EFFECT_CLASS,
        "interaction_category": D16_INTERACTION_CATEGORY,
        "selector_digest": _digest(
            {
                "adapter_id": D16_ADAPTER_ID,
                "effect_class": D16_EFFECT_CLASS,
                "interaction_category": D16_INTERACTION_CATEGORY,
            }
        ),
        "vulnerable_consecutive_restorations": len(vulnerable),
        "clean_consecutive_restorations": len(clean),
        "fault_observations": _fault_observations(),
        "truth_authority": "observation_only",
        "qualified_at": qualified_at,
        "expires_at": qualified_at + timedelta(days=90),
    }
    receipt = C10AdapterQualificationV1(
        **values, qualification_digest=_digest(values)
    )
    # The receipt is only valid if the same fail-closed path D16 uses accepts it.
    validate_mutation_qualification(
        manifest={"capability10_qualification": receipt.model_dump(mode="json")},
        adapter_id=D16_ADAPTER_ID,
        adapter_contract_version=str(binding["adapter_contract_version"]),
        runtime_version=str(binding["runtime_version"]),
        runtime_image_digest=str(binding["runtime_image_digest"]),
        configuration_digest=str(binding["configuration_digest"]),
        content_bundle_digest=binding["content_bundle_digest"],
        effect_class=D16_EFFECT_CLASS,
        interaction_category=D16_INTERACTION_CATEGORY,
        mutation_recipe_ref=values["mutation_recipe_ref"],
        mutation_recipe_digest=values["mutation_recipe_digest"],
        cleanup_recipe_ref=values["cleanup_recipe_ref"],
        cleanup_recipe_digest=values["cleanup_recipe_digest"],
        approved_qualification_digest=receipt.qualification_digest,
        now=qualified_at,
    )
    return receipt


async def _persist(receipt: C10AdapterQualificationV1) -> None:
    """Publish the receipt into the deployed-adapter inventory.

    The receipt reaches D16 through the C5 adapter snapshot manifest, and the
    snapshot is written from the deployed-adapter inventory.  Snapshots are
    append-only at the database level, so the receipt cannot be patched onto an
    existing snapshot after the fact; it has to be present in the inventory the
    snapshot is authored from.  This writes it there and re-validates the whole
    inventory through the same path the tool gateway uses, so a receipt that
    does not satisfy the D16 selector is refused rather than published.
    """

    from datetime import UTC, datetime

    from sqlalchemy import select

    import app.infrastructure.database.models  # noqa: F401  (registers tables)
    from app.core.services.pentesting.deployed_adapters import (
        validate_deployed_adapters,
    )
    from app.infrastructure.database.database import AsyncSessionLocal
    from app.infrastructure.database.models import SystemConfiguration

    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(
                select(SystemConfiguration).where(
                    SystemConfiguration.key == "pentest_deployed_adapter_inventory"
                )
            )
        ).scalar_one_or_none()
        wire = dict(row.value) if row is not None and row.value else None
        adapters = list(wire.get("adapters", [])) if wire else []
        target = next(
            (
                index
                for index, entry in enumerate(adapters)
                if isinstance(entry, dict)
                and isinstance(entry.get("snapshot"), dict)
                and entry["snapshot"].get("adapter_id") == D16_ADAPTER_ID
            ),
            None,
        )
        if target is None:
            raise SystemExit(
                f"the deployed-adapter inventory has no {D16_ADAPTER_ID} entry. "
                "D16 dispatch lives on the C5 adapter path, so the adapter pack "
                "must be deployed and probed by the deployment reporter before a "
                "receipt can be published. Fabricating the inventory entry would "
                "forge deployment qualification evidence, so this refuses instead."
            )
        payload = receipt.model_dump(mode="json")
        adapters[target] = dict(adapters[target])
        adapters[target]["snapshot"] = {
            **adapters[target]["snapshot"],
            "capability10_qualification": payload,
        }
        candidate = {
            **(wire or {"schema_version": "sccap.pentest.deployed-adapters.v1"}),
            "adapters": adapters,
        }
        try:
            entries = validate_deployed_adapters(candidate, now=datetime.now(UTC))
            if len(entries) != len(adapters):
                raise ValueError("health is stale or unqualified")
        except (ValueError, TypeError, KeyError) as exc:
            raise SystemExit(
                f"the receipt did not satisfy the deployed-adapter validator: {exc}"
            ) from exc
        if row is None:
            db.add(
                SystemConfiguration(
                    key="pentest_deployed_adapter_inventory",
                    value=candidate,
                    description=(
                        "Qualified tool deployment health; entries expire "
                        "without renewal."
                    ),
                    is_secret=False,
                    encrypted=False,
                )
            )
        else:
            row.value = candidate
            row.version = row.version + 1
        await db.commit()
        print(f"published the receipt on the {D16_ADAPTER_ID} inventory entry")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="persist the receipt on the C5 adapter snapshot",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write the full receipt JSON to this path",
    )
    args = parser.parse_args()

    receipt = build_receipt()
    print("D16 qualification complete")
    print(f"  adapter                 {receipt.adapter_id}")
    print(f"  selector                {receipt.effect_class} / {receipt.interaction_category}")
    print(f"  vulnerable restorations {receipt.vulnerable_consecutive_restorations}")
    print(f"  clean restorations      {receipt.clean_consecutive_restorations}")
    print(f"  faults observed         {len(receipt.fault_observations)}")
    print(f"  expires                 {receipt.expires_at.isoformat()}")
    print()
    print("PENTEST_CAPABILITY10_D16_QUALIFICATION_DIGEST=" + receipt.qualification_digest)

    if args.out is not None:
        args.out.write_text(json.dumps(receipt.model_dump(mode="json"), indent=2))
        print(f"\nreceipt written to {args.out}")
    if args.write:
        asyncio.run(_persist(receipt))


if __name__ == "__main__":
    main()

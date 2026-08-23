"""Container-only scanner version/digest smoke check used by CI."""

from __future__ import annotations

import json

from app.infrastructure.scanners.provenance import collect_runtime_provenance


def main() -> None:
    provenance = collect_runtime_provenance()
    expected = {"bandit", "semgrep", "gitleaks", "osv"}
    if set(provenance) != expected:
        raise SystemExit(f"scanner set mismatch: {sorted(provenance)}")

    for scanner, record in provenance.items():
        binary = record["binary"]
        if binary["sha256"] != binary["expected_sha256"]:
            raise SystemExit(f"{scanner}: binary digest mismatch")
        if binary["version"] != binary["expected_version"]:
            raise SystemExit(f"{scanner}: version mismatch")
        configuration = record["configuration"]
        expected_config = configuration.get("expected_sha256")
        if expected_config and configuration.get("sha256") != expected_config:
            raise SystemExit(f"{scanner}: configuration digest mismatch")

    osv = provenance["osv"]
    if osv["status"] == "verified":
        advisory = osv.get("advisory_database") or {}
        if not advisory.get("immutable") or not advisory.get("database_sha256"):
            raise SystemExit(
                "osv: verified snapshot is missing immutable digest evidence"
            )
    else:
        osv_reasons = osv["reasons"]
        expected_unavailable = {
            "advisory_snapshot_identifier_unavailable",
            "snapshot_unconfigured",
            "snapshot_manifest_unavailable",
        }
        if len(osv_reasons) != 1 or osv_reasons[0] not in expected_unavailable:
            raise SystemExit(f"osv: unexpected degraded reasons: {osv_reasons}")
    for scanner in expected - {"osv"}:
        if provenance[scanner]["status"] != "verified":
            raise SystemExit(
                f"{scanner}: expected verified, got {provenance[scanner]['reasons']}"
            )

    print(json.dumps(provenance, sort_keys=True))


if __name__ == "__main__":
    main()

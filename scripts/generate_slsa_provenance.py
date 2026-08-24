#!/usr/bin/env python3
"""Emit truthful repository-workflow SLSA provenance for an OCI image."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_HEX_40_OR_64 = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def build_predicate(
    *,
    image: str,
    digest: str,
    revision: str,
    repository: str,
    workflow_ref: str,
    target: str,
    invocation_id: str,
) -> dict:
    digest_algorithm, separator, digest_value = digest.partition(":")
    if digest_algorithm != "sha256" or separator != ":" or not _HEX_64.fullmatch(
        digest_value
    ):
        raise ValueError("--digest must be a lowercase sha256 OCI digest")
    if not _HEX_40_OR_64.fullmatch(revision):
        raise ValueError("--revision must be a full immutable Git object ID")
    if target not in {"api", "worker"}:
        raise ValueError("--target must be api or worker")
    if not workflow_ref.startswith(f"{repository}/.github/workflows/"):
        raise ValueError("--workflow-ref must identify this repository workflow")
    workflow_uri = f"https://github.com/{workflow_ref}"
    return {
        "buildDefinition": {
            # This is SCCAP's pinned GitHub Actions workflow, not the official
            # SLSA generator. Do not upgrade this claim without changing builders.
            "buildType": workflow_uri,
            "externalParameters": {
                "repository": repository,
                "revision": revision,
                "target": target,
                "image": image,
                "imageDigest": f"sha256:{digest_value}",
            },
            "internalParameters": {},
            "resolvedDependencies": [
                {
                    "uri": f"git+https://github.com/{repository}@{revision}",
                    "digest": {"gitCommit": revision},
                }
            ],
        },
        "runDetails": {
            "builder": {"id": workflow_uri},
            "metadata": {"invocationId": invocation_id},
            "byproducts": [],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--invocation-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        predicate = build_predicate(
            image=args.image,
            digest=args.digest,
            revision=args.revision,
            repository=args.repository,
            workflow_ref=args.workflow_ref,
            target=args.target,
            invocation_id=args.invocation_id,
        )
    except ValueError as exc:
        parser.error(str(exc))
    args.output.write_text(
        json.dumps(predicate, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

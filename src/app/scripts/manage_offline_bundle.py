"""Build, verify, activate, resolve, or roll back a signed offline bundle."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from app.infrastructure.governance.offline_bundle import (
    activate_bundle,
    build_bundle,
    resolve_active_bundle,
    rollback_bundle,
    verify_bundle,
)
from app.infrastructure.signing.digest_signer import AwsKmsDigestSigner
from app.infrastructure.signing.public_key_verifier import (
    Ed25519FileDigestSigner,
    PinnedEd25519PublicKeyDigestVerifier,
    PinnedRsaPublicKeyDigestVerifier,
)


def _build_signer() -> AwsKmsDigestSigner:
    key_id = os.environ.get("GOVERNANCE_SIGNING_KMS_KEY_ID", "").strip()
    if not key_id:
        raise RuntimeError(
            "GOVERNANCE_SIGNING_KMS_KEY_ID is required for bundle build."
        )
    return AwsKmsDigestSigner(
        key_id=key_id,
        region=os.environ.get("GOVERNANCE_SIGNING_KMS_REGION", "us-east-1"),
    )


def _release_verifier(args: argparse.Namespace) -> PinnedRsaPublicKeyDigestVerifier:
    key_path = args.release_public_key or os.environ.get(
        "OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY"
    )
    fingerprint = args.release_public_key_sha256 or os.environ.get(
        "OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY_SHA256"
    )
    key_id = args.release_key_id or os.environ.get("OFFLINE_BUNDLE_RELEASE_KEY_ID")
    if not key_path or not fingerprint or not key_id:
        raise RuntimeError(
            "Pinned release public key, SHA-256 fingerprint, and canonical key id are required."
        )
    return PinnedRsaPublicKeyDigestVerifier(
        public_key_path=Path(key_path),
        public_key_sha256=fingerprint,
        expected_key_id=key_id,
    )


def _state_signer(args: argparse.Namespace) -> Ed25519FileDigestSigner:
    key_path = args.deployment_signing_key or os.environ.get(
        "OFFLINE_BUNDLE_DEPLOYMENT_SIGNING_KEY"
    )
    fingerprint = args.deployment_public_key_sha256 or os.environ.get(
        "OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY_SHA256"
    )
    if not key_path or not fingerprint:
        raise RuntimeError(
            "Deployment signing key and pinned public-key SHA-256 fingerprint are required."
        )
    return Ed25519FileDigestSigner(
        private_key_path=Path(key_path), public_key_sha256=fingerprint
    )


def _state_verifier(args: argparse.Namespace) -> PinnedEd25519PublicKeyDigestVerifier:
    key_path = args.deployment_public_key or os.environ.get(
        "OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY"
    )
    fingerprint = args.deployment_public_key_sha256 or os.environ.get(
        "OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY_SHA256"
    )
    if not key_path or not fingerprint:
        raise RuntimeError(
            "Pinned deployment public key and SHA-256 fingerprint are required."
        )
    return PinnedEd25519PublicKeyDigestVerifier(
        public_key_path=Path(key_path), public_key_sha256=fingerprint
    )


async def _run(args: argparse.Namespace) -> dict:
    if args.command == "build":
        verified = await build_bundle(
            output=args.bundle,
            version=args.version,
            components={
                "scanners": args.scanners,
                "rules": args.rules,
                "advisory": args.advisory,
            },
            signer=_build_signer(),
            source_date_epoch=args.source_date_epoch,
        )
    elif args.command == "verify":
        verified = await verify_bundle(
            bundle=args.bundle, signer=_release_verifier(args)
        )
    elif args.command == "activate":
        verified = await activate_bundle(
            bundle=args.bundle,
            install_root=args.install_root,
            signer=_release_verifier(args),
            state_signer=_state_signer(args),
        )
    elif args.command == "rollback":
        return {
            "rolled_back_to": await rollback_bundle(
                install_root=args.install_root,
                signer=_release_verifier(args),
                state_signer=_state_signer(args),
            )
        }
    else:
        paths = await resolve_active_bundle(
            install_root=args.install_root,
            signer=_release_verifier(args),
            state_signer=_state_verifier(args),
        )
        return {
            "release_sha256": paths.release_sha256,
            "release_root": str(paths.release_root),
            "scanners": str(paths.scanners),
            "rules": str(paths.rules),
            "advisory": str(paths.advisory),
        }
    return {
        "bundle_sha256": verified.bundle_sha256,
        "manifest_sha256": verified.manifest_sha256,
        "version": verified.version,
    }


def _add_release_trust(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release-public-key", type=Path)
    parser.add_argument("--release-public-key-sha256")
    parser.add_argument("--release-key-id")


def _add_deployment_key(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--deployment-signing-key", type=Path)
    parser.add_argument("--deployment-public-key-sha256")


def _add_deployment_public_key(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--deployment-public-key", type=Path)
    parser.add_argument("--deployment-public-key-sha256")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--bundle", type=Path, required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--scanners", type=Path, required=True)
    build.add_argument("--rules", type=Path, required=True)
    build.add_argument("--advisory", type=Path, required=True)
    build.add_argument("--source-date-epoch", type=int, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    _add_release_trust(verify)
    for command in ("activate", "rollback", "resolve"):
        operation = subparsers.add_parser(command)
        operation.add_argument("--install-root", type=Path, required=True)
        if command == "activate":
            operation.add_argument("--bundle", type=Path, required=True)
        _add_release_trust(operation)
        if command == "resolve":
            _add_deployment_public_key(operation)
        else:
            _add_deployment_key(operation)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(_run(args)), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

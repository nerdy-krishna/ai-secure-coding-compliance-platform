"""Fail-closed worker bootstrap for an activated restricted-egress bundle."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Mapping, MutableMapping

from app.infrastructure.governance.offline_bundle import (
    OfflineRuntimePaths,
    resolve_active_bundle,
)
from app.infrastructure.signing.public_key_verifier import (
    PinnedEd25519PublicKeyDigestVerifier,
    PinnedRsaPublicKeyDigestVerifier,
)

INSTALL_ROOT_ENV = "SCCAP_OFFLINE_INSTALL_ROOT"
MAX_SCANNER_BINARY_BYTES = 512 * 1024 * 1024


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required when {INSTALL_ROOT_ENV} is configured.")
    return value


def _sha256_file(path: Path, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise RuntimeError(f"Verified runtime file exceeds its limit: {path.name}")
            digest.update(chunk)
    return digest.hexdigest()


async def configure_offline_runtime_from_environment(
    environment: MutableMapping[str, str] | None = None,
) -> OfflineRuntimePaths | None:
    """Verify signed state/content, then expose exact paths to scanner runners.

    Default deployments are unchanged. Once ``SCCAP_OFFLINE_INSTALL_ROOT`` is
    set, incomplete trust configuration or any tamper aborts worker startup.
    """
    env = environment if environment is not None else os.environ
    configured_root = env.get(INSTALL_ROOT_ENV, "").strip()
    if not configured_root:
        return None
    install_root = Path(configured_root).resolve(strict=True)
    release_verifier = PinnedRsaPublicKeyDigestVerifier(
        public_key_path=Path(
            _required(env, "OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY")
        ),
        public_key_sha256=_required(
            env, "OFFLINE_BUNDLE_RELEASE_PUBLIC_KEY_SHA256"
        ),
        expected_key_id=_required(env, "OFFLINE_BUNDLE_RELEASE_KEY_ID"),
    )
    state_verifier = PinnedEd25519PublicKeyDigestVerifier(
        public_key_path=Path(
            _required(env, "OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY")
        ),
        public_key_sha256=_required(
            env, "OFFLINE_BUNDLE_DEPLOYMENT_PUBLIC_KEY_SHA256"
        ),
    )
    paths = await resolve_active_bundle(
        install_root=install_root,
        signer=release_verifier,
        state_signer=state_verifier,
    )
    # These values come only from the verified manifest and immutable release.
    env.update(
        {
            "SCCAP_OFFLINE_VERIFIED_RELEASE_SHA256": paths.release_sha256,
            "SEMGREP_BINARY": str(paths.semgrep_binary),
            "SEMGREP_OFFLINE_RULE_ROOT": str(paths.semgrep_rule_roots[0]),
            "GITLEAKS_BINARY": str(paths.gitleaks_binary),
            "GITLEAKS_CONFIG_PATH": str(paths.gitleaks_config),
            "OSV_BINARY": str(paths.osv_binary),
            "OSV_OFFLINE_SNAPSHOT_DIR": str(paths.osv_advisory_root),
            "SCCAP_SEMGREP_BINARY_SHA256": _sha256_file(
                paths.semgrep_binary, max_bytes=MAX_SCANNER_BINARY_BYTES
            ),
            "SCCAP_GITLEAKS_BINARY_SHA256": _sha256_file(
                paths.gitleaks_binary, max_bytes=MAX_SCANNER_BINARY_BYTES
            ),
            "SCCAP_OSV_BINARY_SHA256": _sha256_file(
                paths.osv_binary, max_bytes=MAX_SCANNER_BINARY_BYTES
            ),
            "SCCAP_GITLEAKS_CONFIG_SHA256": _sha256_file(
                paths.gitleaks_config, max_bytes=4 * 1024 * 1024
            ),
        }
    )
    return paths

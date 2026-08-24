"""Reproducible signed bundles and fail-closed restricted-egress activation."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from app.infrastructure.governance.contracts import canonical_json
from app.infrastructure.signing.digest_signer import DigestSignature, DigestSigner

REQUIRED_COMPONENTS = frozenset({"scanners", "rules", "advisory"})
REQUIRED_SCANNERS = frozenset({"semgrep", "gitleaks", "osv-scanner"})
MAX_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_FILES = 200_000
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SCANNER_VERSION_ARGS: Mapping[str, tuple[str, ...]] = {
    "semgrep": ("--version",),
    "gitleaks": ("version",),
    "osv-scanner": ("--version",),
}
SCANNER_VERSIONS: Mapping[str, str] = {
    "semgrep": "1.95.0",
    "gitleaks": "8.21.2",
    "osv-scanner": "2.3.5",
}
MAX_SCANNER_VERSION_OUTPUT_BYTES = 16 * 1024
ACTIVATION_NETWORK_ISOLATION_ENV = "SCCAP_OFFLINE_ACTIVATION_NETWORK_ISOLATION"
COMPOSE_NETWORK_NONE_MODE = "compose_network_none"
NETWORK_INTERFACE_ROOT = Path("/sys/class/net")
ScannerSmokeRunner = Callable[[Path, tuple[str, ...]], str]


class OfflineBundleError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerifiedBundle:
    bundle_sha256: str
    manifest_sha256: str
    version: str
    manifest: dict[str, Any]


@dataclass(frozen=True)
class OfflineRuntimePaths:
    """Verified runtime roots beneath the active immutable release."""

    release_sha256: str
    release_root: Path
    scanners: Path
    rules: Path
    advisory: Path
    semgrep_binary: Path
    gitleaks_binary: Path
    osv_binary: Path
    semgrep_rule_roots: tuple[Path, ...]
    gitleaks_config: Path
    osv_advisory_root: Path


def _safe_member_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise OfflineBundleError("Bundle contains an unsafe path.")
    return path


def _iter_component_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        if path.is_symlink():
            raise OfflineBundleError("Bundle inputs cannot contain symlinks.")
        if path.is_file():
            files.append(path)
    return files


def _hash_stream(stream: Any, *, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(1024 * 1024):
        size += len(chunk)
        if size > max_bytes:
            raise OfflineBundleError("Content exceeds the accepted size limit.")
        digest.update(chunk)
    return digest.hexdigest(), size


def _hash_file(path: Path, *, max_bytes: int = MAX_BUNDLE_BYTES) -> tuple[str, int]:
    with path.open("rb") as stream:
        return _hash_stream(stream, max_bytes=max_bytes)


def _read_file_limited(path: Path, *, max_bytes: int) -> bytes:
    if path.stat().st_size > max_bytes:
        raise OfflineBundleError("Metadata exceeds the accepted size limit.")
    with path.open("rb") as stream:
        body = stream.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise OfflineBundleError("Metadata exceeds the accepted size limit.")
    return body


def _read_member_limited(
    archive: tarfile.TarFile, name: str, *, max_bytes: int
) -> bytes:
    try:
        member = archive.getmember(name)
    except KeyError as exc:
        raise OfflineBundleError("Offline bundle metadata is missing.") from exc
    if not member.isfile() or member.size > max_bytes:
        raise OfflineBundleError(
            "Offline bundle metadata exceeds the accepted size limit."
        )
    stream = archive.extractfile(member)
    if stream is None:
        raise OfflineBundleError("Offline bundle metadata is unreadable.")
    body = stream.read(max_bytes + 1)
    if len(body) != member.size or len(body) > max_bytes:
        raise OfflineBundleError("Offline bundle metadata size mismatch.")
    return body


def _runtime_contract(entries: list[dict[str, Any]]) -> dict[str, Any]:
    paths = [str(entry["path"]) for entry in entries]
    scanner_paths: dict[str, str] = {}
    for scanner in REQUIRED_SCANNERS:
        matching = [path for path in paths if PurePosixPath(path).name == scanner]
        if len(matching) != 1 or not matching[0].startswith("payload/scanners/"):
            raise OfflineBundleError(
                f"Offline scanner component requires exactly one {scanner} binary."
            )
        entry = next(item for item in entries if item["path"] == matching[0])
        if int(entry["mode"]) & 0o111 == 0:
            raise OfflineBundleError(f"Offline scanner {scanner} must be executable.")
        scanner_paths[scanner] = matching[0]
    semgrep_rules = [
        path
        for path in paths
        if path.startswith("payload/rules/") and path.endswith((".yml", ".yaml"))
    ]
    gitleaks_configs = [
        path
        for path in paths
        if path.startswith("payload/rules/") and path.endswith(".toml")
    ]
    advisory_manifests = [
        path for path in paths if path == "payload/advisory/snapshot.json"
    ]
    advisory_databases = [
        path
        for path in paths
        if path.startswith("payload/advisory/osv-scanner/")
        and path.endswith("/all.zip")
    ]
    if not semgrep_rules or not gitleaks_configs:
        raise OfflineBundleError(
            "Offline rules require Semgrep YAML and a Gitleaks TOML configuration."
        )
    if len(advisory_manifests) != 1 or not advisory_databases:
        raise OfflineBundleError(
            "Offline advisory component requires snapshot.json and OSV all.zip data."
        )
    return {
        "schema_version": 1,
        "scanners": scanner_paths,
        "semgrep_rule_roots": ["payload/rules"],
        "gitleaks_configs": sorted(gitleaks_configs),
        "osv_advisory_roots": ["payload/advisory"],
    }


def _validate_advisory_manifest(body: bytes, entries: list[dict[str, Any]]) -> None:
    try:
        manifest = json.loads(body)
    except json.JSONDecodeError as exc:
        raise OfflineBundleError("OSV snapshot manifest is invalid JSON.") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or not isinstance(manifest.get("snapshot_id"), str)
        or not manifest["snapshot_id"]
        or not isinstance(manifest.get("created_at"), str)
        or not isinstance(manifest.get("files"), list)
        or not manifest["files"]
    ):
        raise OfflineBundleError("OSV snapshot manifest is malformed.")
    expected = {
        str(entry["path"]).removeprefix("payload/advisory/"): entry
        for entry in entries
        if str(entry["path"]).startswith("payload/advisory/osv-scanner/")
        and str(entry["path"]).endswith("/all.zip")
    }
    observed: set[str] = set()
    for item in manifest["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "size_bytes", "sha256"}:
            raise OfflineBundleError("OSV snapshot manifest entry is malformed.")
        relative = _safe_member_name(str(item["path"])).as_posix()
        entry = expected.get(relative)
        if (
            relative in observed
            or entry is None
            or item["size_bytes"] != entry["size"]
            or item["sha256"] != entry["sha256"]
        ):
            raise OfflineBundleError(
                "OSV snapshot manifest does not bind its database."
            )
        observed.add(relative)
    if observed != set(expected):
        raise OfflineBundleError("OSV snapshot manifest does not bind every database.")


def _signature_payload(
    signature: DigestSignature, manifest_digest: bytes
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "manifest_sha256": manifest_digest.hex(),
        "signature_b64": signature.signature_b64,
        "algorithm": signature.algorithm,
        "key_id": signature.key_id,
    }


async def build_bundle(
    *,
    output: Path,
    version: str,
    components: Mapping[str, Path],
    signer: DigestSigner,
    source_date_epoch: int,
) -> VerifiedBundle:
    """Create a byte-reproducible uncompressed tar archive and sign its manifest."""
    if set(components) != REQUIRED_COMPONENTS:
        raise ValueError("Offline bundles require scanners, rules, and advisory roots.")
    if not version.strip() or len(version) > 96:
        raise ValueError("Bundle version is required and limited to 96 characters.")
    entries: list[dict[str, Any]] = []
    source_files: list[tuple[str, Path, int]] = []
    total_size = 0
    for component in sorted(components):
        root = components[component].resolve(strict=True)
        files = _iter_component_files(root)
        if not files:
            raise OfflineBundleError(f"Offline bundle component {component} is empty.")
        for path in files:
            relative = path.relative_to(root).as_posix()
            archive_path = f"payload/{component}/{relative}"
            digest, size = _hash_file(path)
            total_size += size
            if total_size > MAX_BUNDLE_BYTES:
                raise OfflineBundleError(
                    "Offline bundle payload exceeds the safety cap."
                )
            mode = (
                0o555 if component == "scanners" and os.access(path, os.X_OK) else 0o444
            )
            entries.append(
                {
                    "path": archive_path,
                    "component": component,
                    "sha256": digest,
                    "size": size,
                    "mode": mode,
                }
            )
            source_files.append((archive_path, path, mode))
    if len(entries) > MAX_FILES:
        raise OfflineBundleError("Offline bundle file count exceeds the safety cap.")
    runtime_contract = _runtime_contract(entries)
    _validate_advisory_manifest(
        _read_file_limited(
            components["advisory"].resolve(strict=True) / "snapshot.json",
            max_bytes=MAX_METADATA_BYTES,
        ),
        entries,
    )
    manifest = {
        "schema_version": 1,
        "version": version.strip(),
        "source_date_epoch": int(source_date_epoch),
        "components": sorted(REQUIRED_COMPONENTS),
        "runtime_contract": runtime_contract,
        "entries": entries,
    }
    manifest_bytes = canonical_json(manifest)
    if len(manifest_bytes) > MAX_METADATA_BYTES:
        raise OfflineBundleError("Offline bundle manifest exceeds the safety cap.")
    manifest_digest = hashlib.sha256(manifest_bytes).digest()
    signature = await signer.sign_sha256(manifest_digest)
    signature_bytes = canonical_json(_signature_payload(signature, manifest_digest))
    estimated_size = 1024 + sum(
        4096 + ((size + 511) // 512) * 512
        for size in [
            len(manifest_bytes),
            len(signature_bytes),
            *(int(entry["size"]) for entry in entries),
        ]
    )
    if estimated_size > MAX_BUNDLE_BYTES:
        raise OfflineBundleError(
            "Offline bundle plus archive overhead exceeds the safety cap."
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w+b") as raw_archive:
            with tarfile.open(
                fileobj=raw_archive, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for name, data in (
                    ("manifest.json", manifest_bytes),
                    ("signature.json", signature_bytes),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = source_date_epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
                for archive_path, source, mode in source_files:
                    info = archive.gettarinfo(str(source), arcname=archive_path)
                    info.mode = mode
                    info.mtime = source_date_epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with source.open("rb") as stream:
                        archive.addfile(info, stream)
            raw_archive.flush()
            if raw_archive.tell() > MAX_BUNDLE_BYTES:
                raise OfflineBundleError("Offline bundle exceeds the safety cap.")
            os.fsync(raw_archive.fileno())
        os.replace(temporary, output)
        _fsync_directory(output.parent)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
    return await verify_bundle(bundle=output, signer=signer)


def _parse_manifest(manifest_bytes: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise OfflineBundleError("Offline bundle manifest is invalid JSON.") from exc
    if not isinstance(manifest, dict) or canonical_json(manifest) != manifest_bytes:
        raise OfflineBundleError("Offline bundle manifest is not canonical JSON.")
    if manifest.get("schema_version") != 1:
        raise OfflineBundleError("Unsupported offline bundle manifest version.")
    if set(manifest.get("components", [])) != REQUIRED_COMPONENTS:
        raise OfflineBundleError("Offline bundle is missing a required component.")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise OfflineBundleError("Offline bundle manifest has no entries.")
    if len(entries) > MAX_FILES:
        raise OfflineBundleError("Offline bundle file count exceeds the safety cap.")
    validated: list[dict[str, Any]] = []
    total_size = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "component",
            "sha256",
            "size",
            "mode",
        }:
            raise OfflineBundleError("Offline bundle manifest entry is malformed.")
        name = _safe_member_name(str(entry["path"])).as_posix()
        component = entry["component"]
        digest = entry["sha256"]
        size = entry["size"]
        mode = entry["mode"]
        if (
            component not in REQUIRED_COMPONENTS
            or not name.startswith(f"payload/{component}/")
            or not _HEX_64.fullmatch(str(digest))
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(mode, int)
            or mode not in {0o444, 0o555}
        ):
            raise OfflineBundleError("Offline bundle manifest entry is malformed.")
        total_size += size
        if total_size > MAX_BUNDLE_BYTES:
            raise OfflineBundleError("Offline bundle payload exceeds the safety cap.")
        validated.append(entry)
    if manifest.get("runtime_contract") != _runtime_contract(validated):
        raise OfflineBundleError("Offline bundle runtime contract is invalid.")
    return manifest


def _parse_signature(signature_bytes: bytes, manifest_digest: bytes) -> DigestSignature:
    try:
        body = json.loads(signature_bytes)
    except json.JSONDecodeError as exc:
        raise OfflineBundleError("Offline bundle signature is invalid JSON.") from exc
    if not isinstance(body, dict) or canonical_json(body) != signature_bytes:
        raise OfflineBundleError("Offline bundle signature is not canonical JSON.")
    if (
        set(body)
        != {
            "schema_version",
            "manifest_sha256",
            "signature_b64",
            "algorithm",
            "key_id",
        }
        or body.get("schema_version") != 1
    ):
        raise OfflineBundleError("Offline bundle signature metadata is malformed.")
    if body.get("manifest_sha256") != manifest_digest.hex():
        raise OfflineBundleError("Offline bundle manifest digest mismatch.")
    return DigestSignature(
        signature_b64=str(body["signature_b64"]),
        algorithm=str(body["algorithm"]),
        key_id=str(body["key_id"]),
    )


async def verify_bundle(*, bundle: Path, signer: DigestSigner) -> VerifiedBundle:
    stat_result = bundle.stat()
    if not stat.S_ISREG(stat_result.st_mode) or not stat_result.st_size:
        raise OfflineBundleError("Offline bundle must be a non-empty regular file.")
    if stat_result.st_size > MAX_BUNDLE_BYTES:
        raise OfflineBundleError("Offline bundle size is outside the accepted range.")
    with tarfile.open(bundle, mode="r:") as archive:
        members = archive.getmembers()
        if len(members) > MAX_FILES + 2:
            raise OfflineBundleError(
                "Offline bundle file count exceeds the safety cap."
            )
        if any(
            not member.isfile() or member.issym() or member.islnk()
            for member in members
        ):
            raise OfflineBundleError("Offline bundles may contain regular files only.")
        names = [_safe_member_name(member.name).as_posix() for member in members]
        if len(names) != len(set(names)):
            raise OfflineBundleError("Offline bundle contains duplicate paths.")
        manifest_bytes = _read_member_limited(
            archive, "manifest.json", max_bytes=MAX_METADATA_BYTES
        )
        signature_bytes = _read_member_limited(
            archive, "signature.json", max_bytes=MAX_METADATA_BYTES
        )
        manifest = _parse_manifest(manifest_bytes)
        manifest_digest = hashlib.sha256(manifest_bytes).digest()
        signature = _parse_signature(signature_bytes, manifest_digest)
        if not await signer.verify_sha256(manifest_digest, signature):
            raise OfflineBundleError("Offline bundle signature is invalid.")
        _validate_advisory_manifest(
            _read_member_limited(
                archive,
                "payload/advisory/snapshot.json",
                max_bytes=MAX_METADATA_BYTES,
            ),
            manifest["entries"],
        )
        expected_names = {"manifest.json", "signature.json"}
        observed_components: set[str] = set()
        for entry in manifest["entries"]:
            name = str(entry["path"])
            expected_names.add(name)
            observed_components.add(str(entry["component"]))
            try:
                member = archive.getmember(name)
            except KeyError as exc:
                raise OfflineBundleError("Offline bundle payload is missing.") from exc
            if member.size != entry["size"] or member.mode & 0o777 != entry["mode"]:
                raise OfflineBundleError("Offline bundle payload metadata mismatch.")
            stream = archive.extractfile(member)
            if stream is None:
                raise OfflineBundleError("Offline bundle payload is unreadable.")
            digest, size = _hash_stream(stream, max_bytes=int(entry["size"]))
            if size != entry["size"] or digest != entry["sha256"]:
                raise OfflineBundleError("Offline bundle payload digest mismatch.")
        if observed_components != REQUIRED_COMPONENTS or set(names) != expected_names:
            raise OfflineBundleError(
                "Offline bundle members do not match the manifest."
            )
    bundle_digest, _ = _hash_file(bundle)
    return VerifiedBundle(
        bundle_sha256=bundle_digest,
        manifest_sha256=manifest_digest.hex(),
        version=str(manifest["version"]),
        manifest=manifest,
    )


async def _verify_installed_release(
    *, release_root: Path, signer: DigestSigner
) -> VerifiedBundle:
    metadata = release_root / ".sccap"
    if (
        release_root.is_symlink()
        or not release_root.is_dir()
        or stat.S_IMODE(release_root.stat().st_mode) != 0o555
        or not metadata.is_dir()
        or stat.S_IMODE(metadata.stat().st_mode) != 0o555
    ):
        raise OfflineBundleError(
            "Installed offline bundle directory modes are invalid."
        )
    for metadata_name in ("manifest.json", "signature.json"):
        metadata_path = metadata / metadata_name
        if (
            metadata_path.is_symlink()
            or not metadata_path.is_file()
            or stat.S_IMODE(metadata_path.stat().st_mode) != 0o444
        ):
            raise OfflineBundleError(
                "Installed offline bundle metadata modes are invalid."
            )
    manifest_bytes = _read_file_limited(
        metadata / "manifest.json", max_bytes=MAX_METADATA_BYTES
    )
    signature_bytes = _read_file_limited(
        metadata / "signature.json", max_bytes=MAX_METADATA_BYTES
    )
    manifest = _parse_manifest(manifest_bytes)
    _validate_advisory_manifest(
        _read_file_limited(
            release_root / "advisory" / "snapshot.json",
            max_bytes=MAX_METADATA_BYTES,
        ),
        manifest["entries"],
    )
    manifest_digest = hashlib.sha256(manifest_bytes).digest()
    signature = _parse_signature(signature_bytes, manifest_digest)
    if not await signer.verify_sha256(manifest_digest, signature):
        raise OfflineBundleError("Installed offline bundle signature is invalid.")
    expected: set[str] = set()
    for entry in manifest["entries"]:
        relative = PurePosixPath(str(entry["path"])).relative_to("payload")
        path = release_root.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise OfflineBundleError("Installed offline bundle payload is unavailable.")
        digest, size = _hash_file(path, max_bytes=int(entry["size"]))
        if (
            size != entry["size"]
            or digest != entry["sha256"]
            or stat.S_IMODE(path.stat().st_mode) != entry["mode"]
        ):
            raise OfflineBundleError("Installed offline bundle payload is invalid.")
        expected.add(relative.as_posix())
    observed: set[str] = set()
    for path in release_root.rglob("*"):
        if path.is_symlink():
            raise OfflineBundleError(
                "Installed offline bundle cannot contain symlinks."
            )
        if path.is_dir() and stat.S_IMODE(path.stat().st_mode) != 0o555:
            raise OfflineBundleError(
                "Installed offline bundle directory modes are invalid."
            )
        if path.is_file() and metadata not in path.parents:
            observed.add(path.relative_to(release_root).as_posix())
    if observed != expected:
        raise OfflineBundleError(
            "Installed offline bundle contains unexpected content."
        )
    return VerifiedBundle(
        bundle_sha256=release_root.name,
        manifest_sha256=manifest_digest.hex(),
        version=str(manifest["version"]),
        manifest=manifest,
    )


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _state_signature(body: Mapping[str, Any]) -> DigestSignature:
    try:
        return DigestSignature(
            signature_b64=str(body["signature_b64"]),
            algorithm=str(body["algorithm"]),
            key_id=str(body["key_id"]),
        )
    except KeyError as exc:
        raise OfflineBundleError("Deployment state signature is malformed.") from exc


async def _load_state(
    path: Path, *, state_signer: DigestSigner
) -> dict[str, Any] | None:
    if not path.exists():
        return None
    body = _read_file_limited(path, max_bytes=MAX_STATE_BYTES)
    try:
        envelope = json.loads(body)
    except json.JSONDecodeError as exc:
        raise OfflineBundleError("Deployment state is invalid JSON.") from exc
    if not isinstance(envelope, dict) or canonical_json(envelope) != body:
        raise OfflineBundleError("Deployment state is not canonical JSON.")
    if (
        set(envelope) != {"schema_version", "ledger", "signature"}
        or envelope.get("schema_version") != 1
    ):
        raise OfflineBundleError("Deployment state envelope is malformed.")
    ledger = envelope["ledger"]
    signature_body = envelope["signature"]
    if not isinstance(ledger, dict) or not isinstance(signature_body, dict):
        raise OfflineBundleError("Deployment state envelope is malformed.")
    ledger_digest = hashlib.sha256(canonical_json(ledger)).digest()
    if signature_body.get("ledger_sha256") != ledger_digest.hex():
        raise OfflineBundleError("Deployment state digest mismatch.")
    if not await state_signer.verify_sha256(
        ledger_digest, _state_signature(signature_body)
    ):
        raise OfflineBundleError("Deployment state signature is invalid.")
    _validate_ledger(ledger)
    return ledger


def _validate_ledger(ledger: dict[str, Any]) -> None:
    if (
        set(ledger) != {"schema_version", "active", "history", "entries"}
        or ledger.get("schema_version") != 1
    ):
        raise OfflineBundleError("Deployment ledger is malformed.")
    active = ledger["active"]
    history = ledger["history"]
    entries = ledger["entries"]
    if not isinstance(active, str) or not _HEX_64.fullmatch(active):
        raise OfflineBundleError("Deployment ledger active release is invalid.")
    if (
        not isinstance(history, list)
        or not all(
            isinstance(item, str) and _HEX_64.fullmatch(item) for item in history
        )
        or not isinstance(entries, list)
        or not entries
    ):
        raise OfflineBundleError("Deployment ledger history is malformed.")
    previous_hash: str | None = None
    previous_active: str | None = None
    reconstructed_history: list[str] = []
    for sequence, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict) or set(entry) != {
            "sequence",
            "action",
            "from",
            "to",
            "release_manifest_sha256",
            "previous_entry_sha256",
            "occurred_at",
        }:
            raise OfflineBundleError("Deployment ledger entry is malformed.")
        if (
            entry["sequence"] != sequence
            or entry["action"] not in {"activate", "rollback"}
            or entry["from"] != previous_active
            or not isinstance(entry["to"], str)
            or not _HEX_64.fullmatch(entry["to"])
            or not _HEX_64.fullmatch(str(entry["release_manifest_sha256"]))
            or entry["previous_entry_sha256"] != previous_hash
            or not isinstance(entry["occurred_at"], str)
        ):
            raise OfflineBundleError("Deployment ledger entry chain is invalid.")
        if entry["action"] == "activate":
            reconstructed_history = [
                item for item in reconstructed_history if item != entry["to"]
            ]
            if previous_active:
                reconstructed_history.append(previous_active)
        else:
            if not reconstructed_history or reconstructed_history[-1] != entry["to"]:
                raise OfflineBundleError(
                    "Deployment ledger rollback history is invalid."
                )
            reconstructed_history.pop()
            if previous_active:
                reconstructed_history = [
                    item for item in reconstructed_history if item != previous_active
                ]
                reconstructed_history.append(previous_active)
        reconstructed_history = reconstructed_history[-20:]
        previous_hash = hashlib.sha256(canonical_json(entry)).hexdigest()
        previous_active = entry["to"]
    if previous_active != active or reconstructed_history != history:
        raise OfflineBundleError(
            "Deployment ledger active release does not match its chain."
        )


def _verify_active_manifest_binding(
    state: Mapping[str, Any], verified: VerifiedBundle
) -> None:
    latest = state["entries"][-1]
    if (
        verified.bundle_sha256 != state["active"]
        or verified.manifest_sha256 != latest["release_manifest_sha256"]
    ):
        raise OfflineBundleError(
            "Active release does not match signed deployment state."
        )


async def _write_state(
    path: Path, *, ledger: dict[str, Any], state_signer: DigestSigner
) -> None:
    _validate_ledger(ledger)
    ledger_digest = hashlib.sha256(canonical_json(ledger)).digest()
    signature = await state_signer.sign_sha256(ledger_digest)
    envelope = {
        "schema_version": 1,
        "ledger": ledger,
        "signature": {
            "ledger_sha256": ledger_digest.hex(),
            "signature_b64": signature.signature_b64,
            "algorithm": signature.algorithm,
            "key_id": signature.key_id,
        },
    }
    body = canonical_json(envelope)
    if len(body) > MAX_STATE_BYTES:
        raise OfflineBundleError("Deployment ledger exceeds the safety cap.")
    _atomic_bytes(path, body)


def _next_ledger(
    previous: dict[str, Any] | None,
    *,
    action: str,
    target: VerifiedBundle,
    occurred_at: str,
) -> dict[str, Any]:
    entries = list(previous["entries"]) if previous else []
    current = previous["active"] if previous else None
    history = list(previous["history"]) if previous else []
    if action == "activate":
        history = [item for item in history if item != target.bundle_sha256]
        if current:
            history.append(current)
    else:
        if not history or history[-1] != target.bundle_sha256:
            raise OfflineBundleError(
                "Rollback target does not match deployment history."
            )
        history.pop()
        if current:
            history = [item for item in history if item != current]
            history.append(current)
    previous_hash = (
        hashlib.sha256(canonical_json(entries[-1])).hexdigest() if entries else None
    )
    entries.append(
        {
            "sequence": len(entries) + 1,
            "action": action,
            "from": current,
            "to": target.bundle_sha256,
            "release_manifest_sha256": target.manifest_sha256,
            "previous_entry_sha256": previous_hash,
            "occurred_at": occurred_at,
        }
    )
    return {
        "schema_version": 1,
        "active": target.bundle_sha256,
        "history": history[-20:],
        "entries": entries,
    }


async def _install_release(
    *, bundle: Path, verified: VerifiedBundle, destination: Path, signer: DigestSigner
) -> None:
    if destination.is_symlink():
        raise OfflineBundleError("Offline release destination cannot be a symlink.")
    if destination.exists():
        await _verify_installed_release(release_root=destination, signer=signer)
        return
    temporary = Path(tempfile.mkdtemp(prefix=".activate-", dir=destination.parent))
    try:
        with tarfile.open(bundle, mode="r:") as archive:
            metadata = temporary / ".sccap"
            metadata.mkdir(mode=0o700)
            (metadata / "manifest.json").write_bytes(
                _read_member_limited(
                    archive, "manifest.json", max_bytes=MAX_METADATA_BYTES
                )
            )
            (metadata / "signature.json").write_bytes(
                _read_member_limited(
                    archive, "signature.json", max_bytes=MAX_METADATA_BYTES
                )
            )
            for entry in verified.manifest["entries"]:
                member = archive.getmember(entry["path"])
                relative = PurePosixPath(entry["path"]).relative_to("payload")
                target = temporary.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise OfflineBundleError("Offline bundle payload is unreadable.")
                with target.open("xb") as output:
                    remaining = int(entry["size"])
                    while remaining:
                        chunk = stream.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise OfflineBundleError(
                                "Offline bundle payload is truncated."
                            )
                        output.write(chunk)
                        remaining -= len(chunk)
                    if stream.read(1):
                        raise OfflineBundleError(
                            "Offline bundle payload exceeds manifest size."
                        )
                target.chmod(int(entry["mode"]))
        _finalize_release_permissions(temporary)
        await _verify_installed_release(release_root=temporary, signer=signer)
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    except Exception:
        _make_tree_owner_writable(temporary)
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _finalize_release_permissions(root: Path) -> None:
    metadata = root / ".sccap"
    for name in ("manifest.json", "signature.json"):
        (metadata / name).chmod(0o444)
    directories = sorted(
        (path for path in root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        directory.chmod(0o555)
    root.chmod(0o555)


def _make_tree_owner_writable(root: Path) -> None:
    if not root.exists():
        return
    try:
        root.chmod(0o700)
        for path in root.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
            elif path.is_file():
                path.chmod(0o600)
    except OSError:
        return


def _limit_child_output() -> None:
    import resource

    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_SCANNER_VERSION_OUTPUT_BYTES, MAX_SCANNER_VERSION_OUTPUT_BYTES),
    )


def _networkless_scanner_version(binary: Path, arguments: tuple[str, ...]) -> str:
    isolation_mode = os.getenv(ACTIVATION_NETWORK_ISOLATION_ENV, "").strip()
    if isolation_mode != COMPOSE_NETWORK_NONE_MODE:
        raise OfflineBundleError(
            "Activation requires the deployment-owned network-isolation marker."
        )
    try:
        interfaces = {path.name for path in NETWORK_INTERFACE_ROOT.iterdir()}
    except OSError as exc:
        raise OfflineBundleError(
            "Activation network isolation cannot be verified."
        ) from exc
    if not interfaces or interfaces - {"lo"}:
        raise OfflineBundleError(
            "Activation manager is not running inside Compose network_mode none."
        )
    with tempfile.TemporaryFile(mode="w+b") as captured:
        completed = subprocess.run(
            [str(binary), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=captured,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=20,
            cwd="/",
            env={
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": f"{binary.parent}:/usr/bin:/bin",
            },
            preexec_fn=_limit_child_output,
        )
        captured.seek(0, os.SEEK_END)
        if captured.tell() > MAX_SCANNER_VERSION_OUTPUT_BYTES:
            raise OfflineBundleError("Scanner version output exceeds the safety cap.")
        captured.seek(0)
        output = captured.read(MAX_SCANNER_VERSION_OUTPUT_BYTES).decode(
            "utf-8", errors="replace"
        )
    if completed.returncode != 0:
        raise OfflineBundleError("Scanner failed activation smoke test.")
    return output


def _verify_scanner_runtime(
    paths: OfflineRuntimePaths, *, runner: ScannerSmokeRunner
) -> None:
    binaries = {
        "semgrep": paths.semgrep_binary,
        "gitleaks": paths.gitleaks_binary,
        "osv-scanner": paths.osv_binary,
    }
    for scanner, binary in binaries.items():
        output = runner(binary, SCANNER_VERSION_ARGS[scanner])
        version = SCANNER_VERSIONS[scanner]
        if not re.search(rf"(?<![0-9.])v?{re.escape(version)}(?![0-9.])", output):
            raise OfflineBundleError(
                f"Offline scanner {scanner} did not report pinned version {version}."
            )


async def activate_bundle(
    *,
    bundle: Path,
    install_root: Path,
    signer: DigestSigner,
    state_signer: DigestSigner,
    occurred_at: str | None = None,
    scanner_smoke_runner: ScannerSmokeRunner | None = None,
) -> VerifiedBundle:
    verified = await verify_bundle(bundle=bundle, signer=signer)
    if install_root.is_symlink():
        raise OfflineBundleError("Offline install root cannot be a symlink.")
    releases = install_root / "releases"
    releases.mkdir(parents=True, exist_ok=True)
    if releases.is_symlink():
        raise OfflineBundleError("Offline releases root cannot be a symlink.")
    destination = _safe_release_path(install_root, verified.bundle_sha256)
    await _install_release(
        bundle=bundle, verified=verified, destination=destination, signer=signer
    )
    installed = await _verify_installed_release(release_root=destination, signer=signer)
    await asyncio.to_thread(
        _verify_scanner_runtime,
        _runtime_paths(destination, installed),
        runner=scanner_smoke_runner or _networkless_scanner_version,
    )
    state_path = install_root / "deployment-state.json"
    previous = await _load_state(state_path, state_signer=state_signer)
    if previous:
        current_verified = await _verify_installed_release(
            release_root=_safe_release_path(install_root, previous["active"]),
            signer=signer,
        )
        _verify_active_manifest_binding(previous, current_verified)
        if previous["active"] == verified.bundle_sha256:
            _atomic_symlink(
                install_root / "current", Path("releases") / verified.bundle_sha256
            )
            return verified
    ledger = _next_ledger(
        previous,
        action="activate",
        target=verified,
        occurred_at=occurred_at or _utc_now(),
    )
    await _write_state(state_path, ledger=ledger, state_signer=state_signer)
    _atomic_symlink(install_root / "current", Path("releases") / verified.bundle_sha256)
    return verified


async def rollback_bundle(
    *,
    install_root: Path,
    signer: DigestSigner,
    state_signer: DigestSigner,
    occurred_at: str | None = None,
) -> str:
    state_path = install_root / "deployment-state.json"
    state = await _load_state(state_path, state_signer=state_signer)
    if state is None:
        raise OfflineBundleError("No signed deployment state is available.")
    current_link = install_root / "current"
    expected_link = Path("releases") / state["active"]
    if (
        not current_link.is_symlink()
        or Path(os.readlink(current_link)) != expected_link
    ):
        active_verified = await _verify_installed_release(
            release_root=_safe_release_path(install_root, state["active"]),
            signer=signer,
        )
        _verify_active_manifest_binding(state, active_verified)
        _atomic_symlink(current_link, expected_link)
        return state["active"]
    history = list(state["history"])
    if not history:
        raise OfflineBundleError("No previous offline bundle is available.")
    previous = history[-1]
    current_verified = await _verify_installed_release(
        release_root=_safe_release_path(install_root, state["active"]), signer=signer
    )
    _verify_active_manifest_binding(state, current_verified)
    verified = await _verify_installed_release(
        release_root=_safe_release_path(install_root, previous), signer=signer
    )
    ledger = _next_ledger(
        state,
        action="rollback",
        target=verified,
        occurred_at=occurred_at or _utc_now(),
    )
    await _write_state(state_path, ledger=ledger, state_signer=state_signer)
    _atomic_symlink(current_link, Path("releases") / previous)
    return previous


async def resolve_active_bundle(
    *, install_root: Path, signer: DigestSigner, state_signer: DigestSigner
) -> OfflineRuntimePaths:
    """Resolve `current` only after signed state and installed content verification."""
    state = await _load_state(
        install_root / "deployment-state.json", state_signer=state_signer
    )
    if state is None:
        raise OfflineBundleError("No signed deployment state is available.")
    current = install_root / "current"
    expected = Path("releases") / state["active"]
    if not current.is_symlink() or Path(os.readlink(current)) != expected:
        raise OfflineBundleError("Active bundle pointer does not match signed state.")
    release_root = _safe_release_path(install_root, state["active"])
    verified = await _verify_installed_release(release_root=release_root, signer=signer)
    _verify_active_manifest_binding(state, verified)
    return _runtime_paths(release_root, verified)


def _runtime_paths(release_root: Path, verified: VerifiedBundle) -> OfflineRuntimePaths:
    return OfflineRuntimePaths(
        release_sha256=verified.bundle_sha256,
        release_root=release_root,
        scanners=release_root / "scanners",
        rules=release_root / "rules",
        advisory=release_root / "advisory",
        semgrep_binary=release_root.joinpath(
            *PurePosixPath(verified.manifest["runtime_contract"]["scanners"]["semgrep"])
            .relative_to("payload")
            .parts
        ),
        gitleaks_binary=release_root.joinpath(
            *PurePosixPath(
                verified.manifest["runtime_contract"]["scanners"]["gitleaks"]
            )
            .relative_to("payload")
            .parts
        ),
        osv_binary=release_root.joinpath(
            *PurePosixPath(
                verified.manifest["runtime_contract"]["scanners"]["osv-scanner"]
            )
            .relative_to("payload")
            .parts
        ),
        semgrep_rule_roots=tuple(
            release_root.joinpath(*PurePosixPath(path).relative_to("payload").parts)
            for path in verified.manifest["runtime_contract"]["semgrep_rule_roots"]
        ),
        gitleaks_config=release_root.joinpath(
            *PurePosixPath(verified.manifest["runtime_contract"]["gitleaks_configs"][0])
            .relative_to("payload")
            .parts
        ),
        osv_advisory_root=release_root.joinpath(
            *PurePosixPath(
                verified.manifest["runtime_contract"]["osv_advisory_roots"][0]
            )
            .relative_to("payload")
            .parts
        ),
    )


def _atomic_bytes(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)


def _atomic_symlink(path: Path, target: Path) -> None:
    temporary: Path | None = None
    for _ in range(10):
        candidate = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
        try:
            candidate.symlink_to(target)
        except FileExistsError:
            continue
        temporary = candidate
        break
    if temporary is None:
        raise OfflineBundleError("Unable to allocate an activation pointer.")
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_release_path(install_root: Path, digest: str) -> Path:
    if not _HEX_64.fullmatch(digest):
        raise OfflineBundleError("Offline release identity is invalid.")
    releases = install_root / "releases"
    if install_root.is_symlink() or releases.is_symlink() or not releases.is_dir():
        raise OfflineBundleError("Offline release root is unsafe.")
    candidate = releases / digest
    if candidate.is_symlink():
        raise OfflineBundleError("Offline release destination cannot be a symlink.")
    try:
        candidate.resolve(strict=False).relative_to(releases.resolve(strict=True))
    except (OSError, ValueError):
        raise OfflineBundleError("Offline release path escapes its root.") from None
    return candidate

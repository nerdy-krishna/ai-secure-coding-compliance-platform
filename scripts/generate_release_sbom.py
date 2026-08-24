#!/usr/bin/env python3
"""Normalize a Syft image SBOM and bind scanner evidence to one OCI digest."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXPECTED_SCANNERS = {
    "api": {"semgrep": "1.95.0", "gitleaks": "8.21.2"},
    "worker": {
        "semgrep": "1.95.0",
        "gitleaks": "8.21.2",
        "osv-scanner": "2.3.5",
    },
}
SCANNER_VERSION_ARGS = {
    "semgrep": ["--version"],
    "gitleaks": ["version"],
    "osv-scanner": ["--version"],
}
MAX_SYFT_SBOM_BYTES = 128 * 1024 * 1024
MAX_INSPECTION_BYTES = 64 * 1024
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")

_INSPECTION_SCRIPT = r"""
import hashlib, json, pathlib, resource, shutil, subprocess, sys, tempfile
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_VERSION_OUTPUT_BYTES = 16 * 1024
version_args = json.loads(sys.argv[-1])
result = []
for name in sys.argv[1:-1]:
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"missing scanner: {name}")
    resolved = pathlib.Path(path).resolve(strict=True)
    if not resolved.is_file() or resolved.stat().st_size > MAX_BINARY_BYTES:
        raise SystemExit(f"invalid scanner binary: {name}")
    def limit_output():
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (MAX_VERSION_OUTPUT_BYTES, MAX_VERSION_OUTPUT_BYTES),
        )
    with tempfile.TemporaryFile(mode="w+b") as captured:
        subprocess.run(
            [str(resolved), *version_args[name]], check=True,
            stdout=captured, stderr=subprocess.STDOUT, timeout=20,
            preexec_fn=limit_output,
        )
        captured.seek(0, 2)
        if captured.tell() > MAX_VERSION_OUTPUT_BYTES:
            raise SystemExit(f"oversized scanner version output: {name}")
        captured.seek(0)
        version_output = captured.read(MAX_VERSION_OUTPUT_BYTES).decode(
            "utf-8", errors="replace"
        ).strip()
    digest = hashlib.sha256()
    size = 0
    with resolved.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_BINARY_BYTES:
                raise SystemExit(f"oversized scanner binary: {name}")
            digest.update(chunk)
    result.append({
        "name": name,
        "path": str(resolved),
        "sha256": digest.hexdigest(),
        "version_output": version_output[:4096],
    })
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
"""


def _read_json(path: Path, *, max_bytes: int) -> dict[str, Any]:
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path} exceeds the accepted size limit")
    value = json.loads(path.read_text("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def inspect_image(image_ref: str, target: str) -> list[dict[str, str]]:
    """Inspect fixed scanner commands in the already-built image, without networking."""
    scanners = sorted(EXPECTED_SCANNERS[target])
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--entrypoint=/usr/local/bin/python",
            image_ref,
            "-c",
            _INSPECTION_SCRIPT,
            *scanners,
            json.dumps(
                {name: SCANNER_VERSION_ARGS[name] for name in scanners},
                sort_keys=True,
                separators=(",", ":"),
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if len(completed.stdout.encode("utf-8")) > MAX_INSPECTION_BYTES:
        raise ValueError("scanner inspection output exceeds the accepted size limit")
    evidence = json.loads(completed.stdout)
    if not isinstance(evidence, list):
        raise ValueError("scanner inspection did not return a JSON list")
    return evidence


def _validate_digest(digest: str) -> str:
    algorithm, separator, value = digest.partition(":")
    if algorithm != "sha256" or separator != ":" or not _HEX_64.fullmatch(value):
        raise ValueError("--digest must be a lowercase sha256 OCI digest")
    return value


def _scanner_components(
    evidence: list[dict[str, str]], *, target: str
) -> list[dict[str, Any]]:
    expected = EXPECTED_SCANNERS[target]
    if len(evidence) != len(expected):
        raise ValueError(f"{target} scanner evidence is incomplete")
    components: list[dict[str, Any]] = []
    observed: set[str] = set()
    for item in evidence:
        if not isinstance(item, dict):
            raise ValueError("scanner evidence entries must be objects")
        name = item.get("name", "")
        output = item.get("version_output", "")
        binary_digest = item.get("sha256", "")
        path = item.get("path", "")
        if name not in expected or name in observed:
            raise ValueError(f"unexpected or duplicate scanner evidence: {name!r}")
        version = expected[name]
        if not re.search(rf"(?<![0-9.])v?{re.escape(version)}(?![0-9.])", output):
            raise ValueError(f"{name} does not report the pinned version {version}")
        if not _HEX_64.fullmatch(binary_digest) or not path.startswith("/"):
            raise ValueError(f"{name} scanner evidence is malformed")
        observed.add(name)
        components.append(
            {
                "type": "file",
                "name": f"{name}-entrypoint",
                "version": version,
                "bom-ref": f"sccap:scanner-entrypoint:{name}:{binary_digest}",
                "hashes": [{"alg": "SHA-256", "content": binary_digest}],
                "properties": [
                    {"name": "sccap:scanner:name", "value": name},
                    {"name": "sccap:image:path", "value": path},
                    {"name": "sccap:image:validated-version", "value": version},
                ],
            }
        )
    if observed != set(expected):
        raise ValueError(f"{target} scanner evidence is incomplete")
    return sorted(components, key=lambda value: value["name"])


def build(
    raw_sbom: dict[str, Any],
    *,
    image: str,
    digest: str,
    target: str,
    revision: str,
    source_date_epoch: int,
    scanner_evidence: list[dict[str, str]],
) -> dict[str, Any]:
    digest_value = _validate_digest(digest)
    if target not in EXPECTED_SCANNERS:
        raise ValueError(f"unsupported image target: {target}")
    if raw_sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("Syft output must be a CycloneDX SBOM")
    if raw_sbom.get("specVersion") not in {"1.5", "1.6"}:
        raise ValueError("Syft image SBOM must use supported CycloneDX 1.5 or 1.6")
    components = raw_sbom.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("Syft image SBOM has no components")
    if not all(isinstance(item, dict) and item.get("name") for item in components):
        raise ValueError("Syft image SBOM contains an invalid component")
    components = [dict(item) for item in components]
    scanner_components = _scanner_components(scanner_evidence, target=target)
    for scanner_component in scanner_components:
        scanner_name = next(
            property_["value"]
            for property_ in scanner_component["properties"]
            if property_["name"] == "sccap:scanner:name"
        )
        package_matches = [
            item
            for item in components
            if str(item.get("name", "")).casefold() == scanner_name
        ]
        if scanner_name == "semgrep" and not any(
            str(item.get("version", "")) == EXPECTED_SCANNERS[target][scanner_name]
            and str(item.get("purl", "")).startswith("pkg:pypi/semgrep@")
            for item in package_matches
        ):
            raise ValueError("Syft SBOM does not bind the pinned Semgrep package")
        if package_matches:
            package_ref = package_matches[0].get("bom-ref") or package_matches[0].get(
                "purl"
            )
            if package_ref:
                scanner_component["properties"].append(
                    {"name": "sccap:syft:package-bom-ref", "value": str(package_ref)}
                )
    components.extend(scanner_components)
    components.sort(
        key=lambda item: (
            str(item.get("purl", "")),
            str(item.get("name", "")),
            str(item.get("version", "")),
        )
    )
    timestamp = datetime.fromtimestamp(source_date_epoch, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    normalized = dict(raw_sbom)
    normalized.update(
        {
            "bomFormat": "CycloneDX",
            "specVersion": raw_sbom.get("specVersion"),
            "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, image + '@' + digest)}",
            "version": 1,
            "components": components,
            "metadata": {
                "timestamp": timestamp,
                "component": {
                    "type": "container",
                    "name": f"sccap-{target}",
                    "version": revision,
                    "bom-ref": f"{image}@{digest}",
                    "hashes": [{"alg": "SHA-256", "content": digest_value}],
                },
                "properties": [
                    {"name": "sccap:image:digest", "value": digest},
                    {"name": "sccap:image:reference", "value": image},
                    {"name": "sccap:image:target", "value": target},
                    {"name": "sccap:source:commit-timestamp", "value": timestamp},
                    {"name": "sccap:source:revision", "value": revision},
                    {"name": "sccap:sbom:generator", "value": "syft-image-scan"},
                ],
                "tools": raw_sbom.get("metadata", {}).get("tools", {}),
            },
        }
    )
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--target", choices=sorted(EXPECTED_SCANNERS), required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
    )
    args = parser.parse_args()
    raw_sbom = _read_json(args.input, max_bytes=MAX_SYFT_SBOM_BYTES)
    image_ref = f"{args.image}@{args.digest}"
    payload = build(
        raw_sbom,
        image=args.image,
        digest=args.digest,
        target=args.target,
        revision=args.revision,
        source_date_epoch=args.source_date_epoch,
        scanner_evidence=inspect_image(image_ref, args.target),
    )
    args.output.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

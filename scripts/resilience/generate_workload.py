"""Generate deterministic SCCAP capacity-test archives.

The archive uses ZIP_STORED so the object uploaded to SCCAP remains close to
the declared workload size.  The contract size is the exact sum of UTF-8 source
bytes, not the ZIP container size.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path

from app.shared.lib.resilience_contract import WORKLOADS, WorkloadProfile


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _content(profile: WorkloadProfile, index: int, size: int) -> bytes:
    prefix = (
        f"# SCCAP deterministic resilience fixture\n"
        f"# profile={profile.value} file={index:05d}\n"
    ).encode("ascii")
    if len(prefix) > size:
        raise ValueError("fixture allocation is too small for its deterministic header")
    remaining = size - len(prefix)
    if remaining == 0:
        return prefix
    # Comment-only padding remains valid Python and avoids triggering scanners.
    return prefix + b"#" + (b"x" * (remaining - 1))


def generate_archive(profile: WorkloadProfile, output: Path, *, force: bool) -> dict:
    if output.exists() and not force:
        raise FileExistsError(f"refusing to overwrite {output}; pass --force explicitly")
    if output.suffix.lower() != ".zip":
        raise ValueError("output must have a .zip suffix")

    file_count, total_bytes = WORKLOADS[profile]
    quotient, remainder = divmod(total_bytes, file_count)
    output.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_STORED,
            allowZip64=True,
        ) as archive:
            for index in range(file_count):
                size = quotient + (1 if index < remainder else 0)
                content = _content(profile, index, size)
                digest.update(content)
                info = zipfile.ZipInfo(
                    filename=f"src/fixture_{index:05d}.py",
                    date_time=(2026, 1, 1, 0, 0, 0),
                )
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, content)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()

    return {
        "schema_version": 1,
        "profile": profile.value,
        "file_count": file_count,
        "total_uncompressed_bytes": total_bytes,
        "content_stream_sha256": digest.hexdigest(),
        "archive_sha256": _file_sha256(output),
        "archive_bytes": output.stat().st_size,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=[profile.value for profile in WorkloadProfile])
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        help="optional path for a JSON digest/size manifest",
    )
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    output_path = args.output.resolve()
    manifest_path = args.manifest.resolve() if args.manifest else None
    if manifest_path == output_path:
        raise ValueError("archive and manifest paths must be different")
    if manifest_path and manifest_path.exists() and not args.force:
        raise FileExistsError(
            f"refusing to overwrite {manifest_path}; pass --force explicitly"
        )
    manifest = generate_archive(
        WorkloadProfile(args.profile), output_path, force=args.force
    )
    rendered = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if manifest_path:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

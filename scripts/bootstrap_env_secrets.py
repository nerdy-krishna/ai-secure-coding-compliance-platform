"""Populate required Compose secrets without disclosing or rotating valid values.

This command is intentionally non-interactive so both setup frontends can use the
same fresh-install and upgrade behavior. It writes the environment file atomically
with owner-only permissions and emits no secret values.
"""

from __future__ import annotations

import argparse
import codecs
import os
import secrets
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from generate_secrets import generate_fernet_key, generate_secret


@dataclass(frozen=True)
class SecretSpec:
    key: str
    generate: Callable[[], str]
    legacy_placeholders: tuple[str, ...] = ()


SECRET_SPECS = (
    SecretSpec("SECRET_KEY", generate_secret),
    SecretSpec("ENCRYPTION_KEY", generate_fernet_key),
    SecretSpec("POSTGRES_PASSWORD", generate_secret),
    SecretSpec("RABBITMQ_DEFAULT_PASS", generate_secret),
    SecretSpec("RABBITMQ_ERLANG_COOKIE", generate_secret),
    SecretSpec(
        "QDRANT_API_KEY",
        generate_secret,
        legacy_placeholders=("change-me-qdrant-key",),
    ),
    SecretSpec("GRAFANA_ADMIN_PASSWORD", generate_secret),
    SecretSpec("LANGFUSE_POSTGRES_PASSWORD", generate_secret),
    SecretSpec("CLICKHOUSE_PASSWORD", generate_secret),
    SecretSpec("REDIS_PASSWORD", generate_secret),
    SecretSpec("MINIO_ROOT_PASSWORD", generate_secret),
    SecretSpec("LANGFUSE_ENCRYPTION_KEY", lambda: secrets.token_hex(32)),
    SecretSpec("LANGFUSE_SALT", generate_secret),
    SecretSpec("NEXTAUTH_SECRET", generate_secret),
    SecretSpec("LANGFUSE_INIT_USER_PASSWORD", generate_secret),
)

DEFAULT_VALUES = {"GRAFANA_ADMIN_USER": "admin"}
DEPRECATED_KEYS = {"RAG_VECTOR_STORE"}


def _is_placeholder(value: str, spec: SecretSpec) -> bool:
    normalized = value.strip()
    if (
        len(normalized) >= 2
        and normalized[0] == normalized[-1]
        and normalized[0]
        in {
            '"',
            "'",
        }
    ):
        normalized = normalized[1:-1]
    return (
        not normalized
        or normalized.startswith("REPLACE_ME")
        or normalized in spec.legacy_placeholders
    )


def _atomic_write_owner_only(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary_path = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:  # Windows exposes chmod(path) but not fchmod(fd).
            os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def bootstrap_env_secrets(path: Path) -> int:
    """Repair missing/placeholding required secrets and return change count."""

    if not path.is_file():
        raise FileNotFoundError(f"Environment file does not exist: {path}")

    raw = path.read_bytes()
    was_utf16 = raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
    original = raw.decode("utf-16" if was_utf16 else "utf-8-sig")
    lines = original.splitlines(keepends=True)
    preferred_newline = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
    current: dict[str, str] = {}
    for line in lines:
        stripped = line.rstrip("\r\n")
        if stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        current[key] = value

    replacements: dict[str, str] = {}
    for spec in SECRET_SPECS:
        if spec.key not in current or _is_placeholder(current[spec.key], spec):
            replacements[spec.key] = spec.generate()
    for key, value in DEFAULT_VALUES.items():
        if not current.get(key):
            replacements[key] = value

    seen: set[str] = set()
    updated_lines: list[str] = []
    for line in lines:
        stripped = line.rstrip("\r\n")
        key = stripped.split("=", 1)[0] if "=" in stripped else ""
        if key in DEPRECATED_KEYS:
            continue
        if key not in replacements:
            updated_lines.append(line)
            continue
        if key not in seen:
            newline = "\r\n" if line.endswith("\r\n") else preferred_newline
            updated_lines.append(f"{key}={replacements[key]}{newline}")
            seen.add(key)

    missing = [key for key in replacements if key not in seen]
    if missing:
        if updated_lines and not updated_lines[-1].endswith(("\n", "\r")):
            updated_lines[-1] += preferred_newline
        updated_lines.extend(
            f"{key}={replacements[key]}{preferred_newline}" for key in missing
        )

    updated = "".join(updated_lines)
    if updated != original or was_utf16 or raw.startswith(codecs.BOM_UTF8):
        _atomic_write_owner_only(path, updated)
    else:
        os.chmod(path, 0o600)
    removed_count = sum(
        1 for line in lines if line.rstrip("\r\n").split("=", 1)[0] in DEPRECATED_KEYS
    )
    return len(replacements) + removed_count


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Populate missing or placeholder SCCAP environment secrets.",
    )
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    args = parser.parse_args(argv)
    changed = bootstrap_env_secrets(args.env_file)
    print(f"Environment secret bootstrap complete ({changed} value(s) repaired).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

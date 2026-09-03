"""Bounded local export-safety verification and immutable redaction transforms.

This is intentionally not a general antivirus engine. It recognizes a closed
set of inert evidence families and rejects anything it cannot completely
inspect under fixed limits.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Literal
from uuid import UUID, uuid5, NAMESPACE_URL

from app.pentesting.contracts.canonical import contract_digest


VERIFIER: Final = "C13-LOCAL-EXPORT-SAFETY-VERIFIER-V1"
MAX_OBJECT_BYTES: Final = 16 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES: Final = 32 * 1024 * 1024
MAX_ARCHIVE_MEMBERS: Final = 1024
MAX_COMPRESSION_RATIO: Final = 20
FIXED_LIMITS: Final = {
    "object_bytes": MAX_OBJECT_BYTES,
    "package_bytes": 64 * 1024 * 1024,
    "selected_objects": 256,
    "archive_expanded_bytes": MAX_ARCHIVE_EXPANDED_BYTES,
    "archive_members": MAX_ARCHIVE_MEMBERS,
    "compression_ratio": MAX_COMPRESSION_RATIO,
    "nested_archives": 0,
}
# A receipt must identify the exact reviewed implementation, not merely a
# friendly version label. This digest changes whenever this module changes.
VERIFIER_IMPLEMENTATION_DIGEST: Final = hashlib.sha256(
    Path(__file__).read_bytes()
).hexdigest()

EvidenceFamily = Literal["http_headers", "json", "text", "zip_archive"]

_EXECUTABLE_MAGIC = (
    b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
)
_ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b")
_ACTIVE = re.compile(
    rb"(?is)<\s*(script|iframe|object|embed|svg|html)\b|javascript\s*:|"
    rb"powershell(?:\.exe)?\b|cmd(?:\.exe)?\s+/c\b|#!/|"
    rb"(?:auto_open|document_open|vbaProject\.bin)|"
    rb"(?:\beval\s*\(|\bexec\s*\(|\brequire\s*\(|\bimport\s*\()"
)
_PRIVATE_KEY = re.compile(
    rb"(?is)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
    rb"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
)
_PRIVATE_KEY_BEGIN = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_AUTHORIZATION = re.compile(
    rb"(?im)^\s*(authorization|proxy-authorization|cookie|set-cookie)\s*:[^\r\n]*"
)
_TOKEN = re.compile(rb"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_SENSITIVE_ASSIGNMENT = re.compile(
    rb"(?im)(?:^|[\"'])\s*(?:x-api-key|api[-_]?key|password|passwd|secret|"
    rb"client[-_]?secret|access[-_]?token|refresh[-_]?token|session(?:[-_]?id|[-_]?token)?|"
    rb"auth[-_]?token|callback[-_]?token|credential(?:s)?|model[-_]?text)\s*[\"']?\s*[:=]\s*"
    rb"(?![\"']?\[REDACTED\])[^\r\n,}]+"
)
_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class C13ExportSafetyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ExportSafetyPolicy:
    policy_id: UUID
    version: int
    evidence_family: EvidenceFamily
    policy_digest: str
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True, slots=True)
class ExportSafetyReceipt:
    evidence_id: UUID
    evidence_version_digest: str
    content_digest: str
    evidence_family: EvidenceFamily
    detected_media_family: str
    policy_id: UUID
    policy_version: int
    policy_digest: str
    verifier: str
    verifier_implementation_digest: str
    outcome: Literal["eligible", "rejected", "unscannable", "incomplete"]
    complete: bool
    limitation_codes: tuple[str, ...]
    verified_at: datetime
    expires_at: datetime
    canonical_digest: str


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    policy_id: UUID
    version: int
    evidence_family: Literal["http_headers", "json", "text"]
    transform: str
    rules_digest: str
    policy_digest: str
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True, slots=True)
class RedactionDerivative:
    child_id: UUID
    child_version_digest: str
    child_content_digest: str
    content: bytes
    receipt_digest: str
    limitation_codes: tuple[str, ...]


def _safe_path(name: str) -> str:
    normalized = unicodedata.normalize("NFC", name.replace("\\", "/"))
    if (
        not normalized or normalized.startswith("/") or "\x00" in normalized
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
        or re.match(r"^[A-Za-z]:", normalized)
        or any(unicodedata.category(ch) in {"Cc", "Cf"} for ch in normalized)
    ):
        raise C13ExportSafetyError("C13_ARCHIVE_PATH_REJECTED")
    return normalized.casefold()


def _scan_forbidden(content: bytes, canaries: tuple[bytes, ...]) -> None:
    if any(content.startswith(magic) for magic in _EXECUTABLE_MAGIC):
        raise C13ExportSafetyError("C13_EXECUTABLE_CONTENT_REJECTED")
    if _EICAR in content:
        raise C13ExportSafetyError("C13_MALWARE_TEST_PATTERN_REJECTED")
    if (
        _PRIVATE_KEY_BEGIN.search(content)
        or _AUTHORIZATION.search(content)
        or _TOKEN.search(content)
        or _SENSITIVE_ASSIGNMENT.search(content)
    ):
        raise C13ExportSafetyError("C13_CATEGORICALLY_FORBIDDEN_CONTENT")
    if any(canary and canary in content for canary in canaries):
        raise C13ExportSafetyError("C13_FORBIDDEN_CANARY_DETECTED")
    if _ACTIVE.search(content):
        raise C13ExportSafetyError("C13_ACTIVE_CONTENT_REJECTED")


def _inspect_zip(content: bytes, canaries: tuple[bytes, ...]) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
        members = archive.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        raise C13ExportSafetyError("C13_ARCHIVE_UNSCANNABLE") from exc
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise C13ExportSafetyError("C13_ARCHIVE_MEMBER_LIMIT")
    names: set[str] = set()
    expanded = 0
    for member in members:
        normalized = _safe_path(member.filename)
        if normalized in names:
            raise C13ExportSafetyError("C13_ARCHIVE_DUPLICATE_PATH")
        names.add(normalized)
        mode = (member.external_attr >> 16) & 0xF000
        if member.flag_bits & 0x1 or mode in {0xC000, 0xA000, 0x6000, 0x2000, 0x1000}:
            raise C13ExportSafetyError("C13_ARCHIVE_SPECIAL_ENTRY_REJECTED")
        expanded += member.file_size
        if expanded > MAX_ARCHIVE_EXPANDED_BYTES or member.file_size > MAX_OBJECT_BYTES:
            raise C13ExportSafetyError("C13_ARCHIVE_SIZE_LIMIT")
        if member.file_size and member.compress_size == 0:
            raise C13ExportSafetyError("C13_ARCHIVE_RATIO_LIMIT")
        if member.compress_size and member.file_size > member.compress_size * MAX_COMPRESSION_RATIO:
            raise C13ExportSafetyError("C13_ARCHIVE_RATIO_LIMIT")
        lower = normalized.rsplit("/", 1)[-1]
        if lower.endswith((".zip", ".gz", ".tar", ".tgz", ".7z", ".rar")):
            raise C13ExportSafetyError("C13_NESTED_ARCHIVE_REJECTED")
        if lower.endswith(
            (
                ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".js",
                ".mjs", ".cjs", ".html", ".htm", ".svg", ".ps1", ".bat",
                ".cmd", ".sh", ".app", ".docm", ".xlsm", ".pptm",
            )
        ):
            raise C13ExportSafetyError("C13_ARCHIVE_ACTIVE_MEMBER_REJECTED")
        try:
            data = archive.read(member)
        except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
            raise C13ExportSafetyError("C13_ARCHIVE_UNSCANNABLE") from exc
        if len(data) != member.file_size or data.startswith(_ARCHIVE_MAGIC):
            raise C13ExportSafetyError("C13_ARCHIVE_UNSCANNABLE")
        _scan_forbidden(data, canaries)


def verify_export_material(
    *, evidence_id: UUID, evidence_version_digest: str, content: bytes,
    family: EvidenceFamily, policy: ExportSafetyPolicy, verified_at: datetime,
    expires_at: datetime, forbidden_canaries: tuple[bytes, ...] = (),
) -> ExportSafetyReceipt:
    if len(content) > MAX_OBJECT_BYTES:
        raise C13ExportSafetyError("C13_EXPORT_OBJECT_SIZE_LIMIT")
    if policy.evidence_family != family or not policy.valid_from <= verified_at < policy.valid_until:
        raise C13ExportSafetyError("C13_VERIFIER_POLICY_STALE")
    if expires_at <= verified_at or expires_at > policy.valid_until:
        raise C13ExportSafetyError("C13_VERIFICATION_EXPIRY_INVALID")
    content_digest = hashlib.sha256(content).hexdigest()
    _scan_forbidden(content, forbidden_canaries)
    media = "application/octet-stream"
    if family == "zip_archive":
        if not content.startswith(b"PK"):
            raise C13ExportSafetyError("C13_MEDIA_FAMILY_MISMATCH")
        _inspect_zip(content, forbidden_canaries)
        media = "application/zip"
    elif family == "json":
        try:
            parsed = json.loads(
                content,
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    ValueError("non-finite JSON value")
                ),
            )
            canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise C13ExportSafetyError("C13_JSON_UNSCANNABLE") from exc
        if len(canonical) > MAX_OBJECT_BYTES:
            raise C13ExportSafetyError("C13_EXPORT_OBJECT_SIZE_LIMIT")
        media = "application/json"
    elif family in {"text", "http_headers"}:
        try:
            content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise C13ExportSafetyError("C13_TEXT_UNSCANNABLE") from exc
        media = "text/plain"
    else:
        raise C13ExportSafetyError("C13_EVIDENCE_FAMILY_UNSUPPORTED")
    payload = {
        "schema": "sccap.pentest.c13-export-verification-receipt.v1",
        "evidence_id": evidence_id, "evidence_version_digest": evidence_version_digest,
        "content_digest": content_digest, "family": family, "media": media,
        "policy_id": policy.policy_id, "policy_version": policy.version,
        "policy_digest": policy.policy_digest, "verifier": VERIFIER,
        "verifier_implementation_digest": VERIFIER_IMPLEMENTATION_DIGEST,
        "limits": FIXED_LIMITS,
        "outcome": "eligible", "complete": True, "limitations": (),
        "verified_at": verified_at, "expires_at": expires_at,
    }
    return ExportSafetyReceipt(
        evidence_id=evidence_id, evidence_version_digest=evidence_version_digest,
        content_digest=content_digest, evidence_family=family,
        detected_media_family=media, policy_id=policy.policy_id,
        policy_version=policy.version, policy_digest=policy.policy_digest,
        verifier=VERIFIER, verifier_implementation_digest=VERIFIER_IMPLEMENTATION_DIGEST,
        outcome="eligible", complete=True, limitation_codes=(),
        verified_at=verified_at, expires_at=expires_at,
        canonical_digest=contract_digest(payload),
    )


def redact_export_material(
    *, source_evidence_id: UUID, source_version_digest: str, source: bytes,
    family: Literal["http_headers", "json", "text"], policy: RedactionPolicy,
) -> RedactionDerivative:
    if policy.evidence_family != family:
        raise C13ExportSafetyError("C13_REDACTION_POLICY_MISMATCH")
    if len(source) > MAX_OBJECT_BYTES:
        raise C13ExportSafetyError("C13_EXPORT_OBJECT_SIZE_LIMIT")
    text = source.decode("utf-8", errors="strict")
    if family == "json":
        try:
            value = json.loads(
                text,
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    ValueError("non-finite JSON value")
                ),
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise C13ExportSafetyError("C13_JSON_UNSCANNABLE") from exc

        def scrub(item: object) -> object:
            if isinstance(item, dict):
                forbidden = {
                    "authorization", "cookie", "set-cookie", "password", "secret", "token",
                    "api_key", "apikey", "private_key", "model_text",
                    "client_secret", "access_token", "refresh_token",
                    "session", "session_id", "session_token", "auth_token",
                    "callback_token", "credential", "credentials",
                }
                return {
                    str(key): (
                        "[REDACTED]"
                        if str(key).casefold().replace("-", "_") in forbidden
                        else scrub(val)
                    )
                    for key, val in item.items()
                }
            if isinstance(item, list):
                return [scrub(value) for value in item]
            return item
        output = json.dumps(scrub(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    else:
        output = _AUTHORIZATION.sub(b"[REDACTED]", source)
        output = _TOKEN.sub(b"[REDACTED]", output)
        output = _SENSITIVE_ASSIGNMENT.sub(b"[REDACTED]", output)
        output = _PRIVATE_KEY.sub(b"[REDACTED PRIVATE KEY]", output)
    _scan_forbidden(output, ())
    content_digest = hashlib.sha256(output).hexdigest()
    child_id = uuid5(NAMESPACE_URL, f"sccap:c13:redaction:{source_evidence_id}:{source_version_digest}:{policy.policy_digest}:{content_digest}")
    version_digest = contract_digest({
        "child_id": child_id, "source_id": source_evidence_id,
        "source_version_digest": source_version_digest,
        "policy_id": policy.policy_id, "policy_version": policy.version,
        "policy_digest": policy.policy_digest, "content_digest": content_digest,
    })
    receipt = contract_digest({
        "schema": "sccap.pentest.c13-redaction-derivative-receipt.v1",
        "child_id": child_id, "child_version_digest": version_digest,
        "child_content_digest": content_digest, "source_id": source_evidence_id,
        "source_version_digest": source_version_digest, "policy_id": policy.policy_id,
        "policy_version": policy.version, "policy_digest": policy.policy_digest,
        "source_content_digest": hashlib.sha256(source).hexdigest(),
        "rules_digest": policy.rules_digest, "verifier": VERIFIER,
        "verifier_implementation_digest": VERIFIER_IMPLEMENTATION_DIGEST,
        "limitation_codes": [],
    })
    return RedactionDerivative(child_id, version_digest, content_digest, output, receipt, ())


__all__ = [
    "C13ExportSafetyError", "ExportSafetyPolicy", "ExportSafetyReceipt",
    "MAX_OBJECT_BYTES", "RedactionDerivative", "RedactionPolicy", "VERIFIER",
    "VERIFIER_IMPLEMENTATION_DIGEST", "redact_export_material",
    "verify_export_material",
]

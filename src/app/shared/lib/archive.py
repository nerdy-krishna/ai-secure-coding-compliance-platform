# src/app/shared/lib/archive.py

import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from typing import List, Dict, Any, Optional

from fastapi import UploadFile, HTTPException

# Assuming get_language_from_filename can be imported from git_utils
# If this causes circular dependency issues or feels misplaced,
# it should be moved to a more general location.
from app.shared.lib.files import get_language_from_filename  # UPDATED IMPORT

logger = logging.getLogger(__name__)

# Magic-byte signatures for supported archive types
_ARCHIVE_MAGIC: dict = {
    ".zip": [(0, b"PK\x03\x04")],
    ".tar.gz": [(0, b"\x1f\x8b")],
    ".tgz": [(0, b"\x1f\x8b")],
    ".tar.bz2": [(0, b"BZh")],
    ".tbz2": [(0, b"BZh")],
    ".tar.xz": [(0, b"\xfd7zXZ\x00")],
    ".txz": [(0, b"\xfd7zXZ\x00")],
    # ustar marker at offset 257 (both "ustar\x00" and "ustar  ")
    ".tar": [(257, b"ustar")],
}


def _safe(s: str) -> str:
    """Sanitise an attacker-supplied string for log output (log injection prevention)."""
    return s.replace("\r", "\\r").replace("\n", "\\n")[:256]


def _verify_archive_magic(archive_path: str, file_extension: str) -> bool:
    """Verify archive content matches the expected magic bytes for the given extension."""
    signatures = _ARCHIVE_MAGIC.get(file_extension)
    if not signatures:
        return False
    try:
        with open(archive_path, "rb") as f:
            for offset, magic in signatures:
                f.seek(offset)
                chunk = f.read(len(magic))
                if chunk == magic:
                    return True
        return False
    except OSError:
        return False


# Configuration for archive extraction security
# These could be moved to settings if more dynamic configuration is needed
MAX_UNCOMPRESSED_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_FILES_IN_ARCHIVE = 5000
ALLOWED_ARCHIVE_EXTENSIONS = (
    ".zip",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar",
)


def _is_path_safe(base_dir: str, target_path_within_archive: str) -> bool:
    """
    Checks if extracting target_path_within_archive into base_dir is safe
    (i.e., does not traverse outside base_dir).
    """
    abs_base_dir = os.path.abspath(base_dir)
    # Create the prospective absolute path of the extracted file
    abs_target_path = os.path.abspath(
        os.path.join(base_dir, target_path_within_archive)
    )
    # Check if the prospective absolute path is still within the base directory
    return abs_target_path.startswith(abs_base_dir)


def _sanitize_extracted_content(content_bytes: bytes) -> str:
    """
    Decodes content bytes to string, attempting UTF-8 then latin-1,
    and removes null bytes.
    """
    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        logger.warning("Could not decode file content as UTF-8, attempting latin-1.")
        try:
            content_str = content_bytes.decode("latin-1")
        except UnicodeDecodeError as e:
            logger.error("Failed to decode file content with UTF-8 and latin-1: %s", e)
            raise HTTPException(
                status_code=400,
                detail="File content encoding not supported (tried UTF-8, latin-1).",
            )
    return content_str.replace("\x00", "")


def extract_archive_to_files(archive_file: UploadFile) -> List[Dict[str, Any]]:
    """
    Extracts files from an uploaded archive (zip or tarball) securely.

    Args:
        archive_file: The UploadFile object representing the archive.

    Returns:
        A list of dictionaries, where each dictionary represents a file
        with 'path', 'content', and 'language'.

    Raises:
        HTTPException if the archive is unsupported, unsafe, or exceeds limits.
    """
    if not archive_file.filename:
        raise HTTPException(status_code=400, detail="Archive filename is missing.")

    # V05.3.2: Reject filenames with path traversal, path separators, or NUL bytes early.
    raw_filename = archive_file.filename
    if (
        "\x00" in raw_filename
        or ".." in raw_filename
        or os.sep in raw_filename
        or (os.altsep and os.altsep in raw_filename)
    ):
        raise HTTPException(
            status_code=400, detail="Archive filename contains invalid characters."
        )

    file_extension = "".join(
        [suffix for suffix in archive_file.filename.lower().split(".") if suffix]
    )
    # More robust extension check for multi-part extensions like .tar.gz
    filename_lower = archive_file.filename.lower()
    is_supported_archive = False
    for ext in ALLOWED_ARCHIVE_EXTENSIONS:
        if filename_lower.endswith(ext):
            is_supported_archive = True
            file_extension = ext  # Use the matched extension for clarity
            break

    if not is_supported_archive:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported archive format for file: {archive_file.filename}. "
            f"Supported formats: {', '.join(ALLOWED_ARCHIVE_EXTENSIONS)}",
        )

    extracted_files_data: List[Dict[str, Any]] = []
    total_uncompressed_size = 0
    file_count = 0

    with tempfile.TemporaryDirectory() as temp_dir:
        # V05.3.2: Use basename only to guarantee the saved file stays within temp_dir.
        safe_archive_name = (
            os.path.basename(archive_file.filename)
            .replace("\x00", "")
            .replace("..", "_")
        )
        archive_path = os.path.join(temp_dir, safe_archive_name)
        try:
            with open(archive_path, "wb") as f_out:
                shutil.copyfileobj(archive_file.file, f_out)
        except Exception as e:
            logger.error("Failed to save uploaded archive: %s", e)
            raise HTTPException(
                status_code=500, detail="Error saving uploaded archive."
            )
        finally:
            archive_file.file.close()  # Ensure the UploadFile stream is closed

        # V05.2.2: Verify magic bytes match the declared extension before opening.
        if not _verify_archive_magic(archive_path, file_extension):
            raise HTTPException(
                status_code=400,
                detail="Archive content does not match its extension.",
            )

        extraction_target_dir = os.path.join(temp_dir, "extracted_content")
        os.makedirs(extraction_target_dir, exist_ok=True)

        try:
            if file_extension == ".zip":
                with zipfile.ZipFile(archive_path, "r") as zf:
                    for member_info in zf.infolist():
                        if member_info.is_dir():
                            continue  # Skip directories

                        # V05.2.5: Skip zip entries whose external attributes indicate a symlink.
                        if (member_info.external_attr >> 16) & 0o170000 == 0o120000:
                            logger.warning(
                                "archive.zip_symlink_skipped path=%s",
                                _safe(member_info.filename),
                            )
                            continue

                        file_count += 1
                        if file_count > MAX_FILES_IN_ARCHIVE:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Archive contains too many files (limit: {MAX_FILES_IN_ARCHIVE}).",
                            )

                        total_uncompressed_size += member_info.file_size
                        if total_uncompressed_size > MAX_UNCOMPRESSED_SIZE_BYTES:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Archive uncompressed size exceeds limit ({MAX_UNCOMPRESSED_SIZE_BYTES // (1024 * 1024)} MB).",
                            )

                        # V15.4.2: Normalise path and reject absolute or traversal paths.
                        normalised_name = os.path.normpath(member_info.filename)
                        if os.path.isabs(normalised_name) or normalised_name.startswith(
                            ".."
                        ):
                            logger.warning(
                                "archive.unsafe_zip_path path=%s",
                                _safe(member_info.filename),
                            )
                            continue

                        if not _is_path_safe(extraction_target_dir, normalised_name):
                            logger.warning(
                                "archive.unsafe_zip_path path=%s",
                                _safe(member_info.filename),
                            )
                            continue

                        # V15.4.2: Read directly from zip into memory (no extract-then-open)
                        # so no symlink/junction file is ever written to disk.
                        try:
                            with zf.open(member_info) as zf_entry:
                                content_bytes = zf_entry.read()
                        except Exception as e:
                            logger.error(
                                "archive.zip_read_error path=%s error=%s",
                                _safe(member_info.filename),
                                e,
                            )
                            continue  # Skip this file

                        content_str = _sanitize_extracted_content(content_bytes)
                        language = get_language_from_filename(member_info.filename)
                        extracted_files_data.append(
                            {
                                "path": member_info.filename,
                                "content": content_str,
                                "language": language or "unknown",
                            }
                        )

            elif (
                file_extension.startswith(".tar")
                or file_extension == ".tgz"
                or file_extension == ".tbz2"
                or file_extension == ".txz"
            ):
                # tarfile.open can handle .tar, .tar.gz, .tar.bz2, .tar.xz automatically
                with tarfile.open(archive_path, "r:*") as tf:
                    # V15.4.2: Use data_filter (Python 3.12+) to atomically reject symlinks,
                    # hardlinks, and absolute/traversal paths inside the extraction call.
                    if hasattr(tarfile, "data_filter"):
                        tf.extraction_filter = tarfile.data_filter  # type: ignore[attr-defined]

                    for member_info in tf.getmembers():
                        # V05.2.5: Explicitly skip symlinks and hardlinks.
                        if member_info.issym() or member_info.islnk():
                            logger.warning(
                                "archive.tar_link_skipped path=%s",
                                _safe(member_info.name),
                            )
                            continue

                        # V05.2.5: Use isreg() (stricter than isfile()) to allow only
                        # regular files.
                        if not member_info.isreg():
                            continue

                        file_count += 1
                        if file_count > MAX_FILES_IN_ARCHIVE:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Archive contains too many files (limit: {MAX_FILES_IN_ARCHIVE}).",
                            )

                        total_uncompressed_size += member_info.size
                        if total_uncompressed_size > MAX_UNCOMPRESSED_SIZE_BYTES:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Archive uncompressed size exceeds limit ({MAX_UNCOMPRESSED_SIZE_BYTES // (1024 * 1024)} MB).",
                            )

                        if not _is_path_safe(extraction_target_dir, member_info.name):
                            logger.warning(
                                "archive.unsafe_tar_path path=%s",
                                _safe(member_info.name),
                            )
                            continue

                        try:
                            # Extract file object directly into memory (no disk write needed).
                            extracted_fo = tf.extractfile(member_info)
                            if extracted_fo:
                                with extracted_fo as f:
                                    content_bytes = f.read()
                            else:
                                # Should not happen if member_info.isreg() is true
                                logger.warning(
                                    "archive.tar_no_fileobj path=%s",
                                    _safe(member_info.name),
                                )
                                continue
                        except Exception as e:
                            logger.error(
                                "archive.tar_read_error path=%s error=%s",
                                _safe(member_info.name),
                                e,
                            )
                            continue  # Skip this file

                        content_str = _sanitize_extracted_content(content_bytes)
                        language = get_language_from_filename(member_info.name)
                        extracted_files_data.append(
                            {
                                "path": member_info.name,
                                "content": content_str,
                                "language": language or "unknown",
                            }
                        )
            else:
                # This case should be caught by the initial extension check
                raise HTTPException(
                    status_code=400, detail="Internal error: Unhandled archive type."
                )

        except HTTPException:  # Re-raise HTTPExceptions
            raise
        except Exception:
            # V16.5.1: Log full details server-side; return only a generic message to the client.
            logger.error(
                "archive.process_failed filename=%s",
                _safe(archive_file.filename),
                exc_info=True,
            )
            raise HTTPException(status_code=500, detail="Error processing archive.")

    if not extracted_files_data:
        raise HTTPException(
            status_code=400,
            detail="No processable files found in the archive or all files were skipped.",
        )
    return extracted_files_data


def is_archive_filename(filename: Optional[str]) -> bool:
    """
    Checks if a filename likely belongs to an archive based on its extension.
    """
    if not filename:
        return False
    filename_lower = filename.lower()
    for ext in ALLOWED_ARCHIVE_EXTENSIONS:
        if filename_lower.endswith(ext):
            return True
    return False


def _is_supported_source_extension(filename: str) -> bool:
    """Check whether a filename has a supported source-code extension."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if not ext:
        return False
    from app.shared.lib.files import LANGUAGE_EXTENSIONS

    return ext in LANGUAGE_EXTENSIONS


def list_archive_files(archive_file: UploadFile) -> List[Dict[str, Any]]:
    """
    Extract an uploaded archive and return metadata for **all** entries.

    Unlike ``extract_archive_to_files`` (which filters to processable files
    and raises when none are found), this returns every regular file in the
    archive, marking each as ``supported=True/False``. The caller (the UI
    file-tree) uses support status to grey out unsupported entries.
    """
    if not archive_file.filename:
        raise HTTPException(status_code=400, detail="Archive filename is missing.")

    raw_filename = archive_file.filename
    if (
        "\x00" in raw_filename
        or ".." in raw_filename
        or os.sep in raw_filename
        or (os.altsep and os.altsep in raw_filename)
    ):
        raise HTTPException(
            status_code=400, detail="Archive filename contains invalid characters."
        )

    filename_lower = archive_file.filename.lower()
    file_extension = ""
    for ext in ALLOWED_ARCHIVE_EXTENSIONS:
        if filename_lower.endswith(ext):
            file_extension = ext
            break

    if not file_extension:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported archive format for file: {archive_file.filename}. "
            f"Supported formats: {', '.join(ALLOWED_ARCHIVE_EXTENSIONS)}",
        )

    entries: List[Dict[str, Any]] = []
    file_count = 0
    total_size = 0

    with tempfile.TemporaryDirectory() as temp_dir:
        safe_name = (
            os.path.basename(archive_file.filename)
            .replace("\x00", "")
            .replace("..", "_")
        )
        archive_path = os.path.join(temp_dir, safe_name)
        try:
            with open(archive_path, "wb") as f_out:
                shutil.copyfileobj(archive_file.file, f_out)
        except Exception:
            raise HTTPException(
                status_code=500, detail="Error saving uploaded archive."
            )
        finally:
            archive_file.file.close()

        if not _verify_archive_magic(archive_path, file_extension):
            raise HTTPException(
                status_code=400,
                detail="Archive content does not match its extension.",
            )

        extraction_dir = os.path.join(temp_dir, "extracted_content")
        os.makedirs(extraction_dir, exist_ok=True)

        try:
            if file_extension == ".zip":
                with zipfile.ZipFile(archive_path, "r") as zf:
                    for mi in zf.infolist():
                        if mi.is_dir():
                            continue
                        if (mi.external_attr >> 16) & 0o170000 == 0o120000:
                            continue
                        normalised = os.path.normpath(mi.filename)
                        if os.path.isabs(normalised) or normalised.startswith(".."):
                            continue
                        if not _is_path_safe(extraction_dir, normalised):
                            continue

                        file_count += 1
                        if file_count > MAX_FILES_IN_ARCHIVE:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Archive contains too many files (limit: {MAX_FILES_IN_ARCHIVE}).",
                            )
                        total_size += mi.file_size
                        if total_size > MAX_UNCOMPRESSED_SIZE_BYTES:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Archive uncompressed size exceeds limit ({MAX_UNCOMPRESSED_SIZE_BYTES // (1024 * 1024)} MB).",
                            )

                        language = get_language_from_filename(mi.filename) or "unknown"
                        supported = _is_supported_source_extension(mi.filename)
                        entries.append(
                            {
                                "path": mi.filename,
                                "language": language,
                                "supported": supported,
                            }
                        )

            elif file_extension.startswith(".tar") or file_extension in (
                ".tgz",
                ".tbz2",
                ".txz",
            ):
                with tarfile.open(archive_path, "r:*") as tf:
                    if hasattr(tarfile, "data_filter"):
                        tf.extraction_filter = tarfile.data_filter

                    for mi in tf.getmembers():
                        if mi.issym() or mi.islnk():
                            continue
                        if not mi.isreg():
                            continue

                        file_count += 1
                        if file_count > MAX_FILES_IN_ARCHIVE:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Archive contains too many files (limit: {MAX_FILES_IN_ARCHIVE}).",
                            )
                        total_size += mi.size
                        if total_size > MAX_UNCOMPRESSED_SIZE_BYTES:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Archive uncompressed size exceeds limit ({MAX_UNCOMPRESSED_SIZE_BYTES // (1024 * 1024)} MB).",
                            )
                        if not _is_path_safe(extraction_dir, mi.name):
                            continue

                        language = get_language_from_filename(mi.name) or "unknown"
                        supported = _is_supported_source_extension(mi.name)
                        entries.append(
                            {
                                "path": mi.name,
                                "language": language,
                                "supported": supported,
                            }
                        )
            else:
                raise HTTPException(
                    status_code=400, detail="Internal error: Unhandled archive type."
                )

        except HTTPException:
            raise
        except Exception:
            logger.error(
                "archive.process_failed filename=%s",
                _safe(archive_file.filename),
                exc_info=True,
            )
            raise HTTPException(status_code=500, detail="Error processing archive.")

    return entries

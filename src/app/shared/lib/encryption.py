# src/app/shared/lib/encryption.py

import logging

from cryptography.fernet import Fernet
from app.config.config import settings

logger = logging.getLogger(__name__)


# Fernet wraps short at-rest secrets (<=64KB plaintext); larger payloads should use a streaming codec.
class FernetEncrypt:
    """
    A utility class for encrypting and decrypting data using Fernet.
    It automatically handles missing base64 padding in the key from the .env file.

    Key rotation requires an application restart; ``_fernet`` is intentionally
    immutable at runtime to keep ``encrypt``/``decrypt`` thread-safe without an
    external lock.  If a runtime rotation API is needed in the future, introduce
    ``_lock = threading.Lock()`` as a class attribute and gate any ``_fernet``
    reassignment with ``with cls._lock: cls._fernet = Fernet(new_key_bytes)``.
    """

    # ENCRYPTION_KEY is a Pydantic SecretStr; unwrap before the base64 padding fix-up.
    _raw_key = settings.ENCRYPTION_KEY
    _key_str = (
        _raw_key.get_secret_value()
        if hasattr(_raw_key, "get_secret_value")
        else str(_raw_key) if _raw_key else ""
    )
    if not _key_str:
        raise ValueError(
            "ENCRYPTION_KEY environment variable not set. Please generate a new one."
        )

    try:
        # Some systems or .env parsers strip '=' padding. We re-add it here.
        # A valid base64 string's length must be a multiple of 4.
        padded_key_str = _key_str + "=" * (-len(_key_str) % 4)

        # The Fernet constructor expects the base64-encoded key as bytes.
        key_as_bytes = padded_key_str.encode("utf-8")

        # The Fernet constructor performs the base64 decoding internally.
        # It will raise a ValueError here if the key is still invalid after padding.
        _fernet = Fernet(key_as_bytes)

    except Exception:
        raise ValueError(
            "Invalid ENCRYPTION_KEY. Could not initialize encryption service. "
            "Ensure it is a URL-safe base64 32-byte key."
        ) from None

    @classmethod
    def encrypt(cls, data: str) -> str:
        """Encrypts a string and returns the encrypted data as a string."""
        if not isinstance(data, str):
            raise TypeError("FernetEncrypt.encrypt: data must be str")
        if len(data) > 64_000:
            raise ValueError("FernetEncrypt.encrypt: data exceeds 64KB cap")
        return cls._fernet.encrypt(data.encode("utf-8")).decode("utf-8")

    @classmethod
    def decrypt(cls, encrypted_data: str) -> str:
        """Decrypts an encrypted string and returns the original data."""
        if not isinstance(encrypted_data, str):
            raise TypeError("FernetEncrypt.decrypt: encrypted_data must be str")
        if len(encrypted_data) > 100_000 or len(encrypted_data) < 20:
            raise ValueError("FernetEncrypt.decrypt: token length out of range")
        try:
            return cls._fernet.decrypt(encrypted_data.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            logger.warning("encryption.decrypt_failed err=%s", type(exc).__name__)
            raise

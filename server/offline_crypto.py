"""
MultiPrint Offline Authorization Cryptography

Server-side Ed25519 signing utilities.

IMPORTANT:
- The private key must NEVER be placed in the desktop application.
- The private key is loaded from the OFFLINE_LICENSE_PRIVATE_KEY
  environment variable.
- The desktop application will only receive/embed the public key.
"""

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


PRIVATE_KEY_ENV_NAME = "OFFLINE_LICENSE_PRIVATE_KEY"


# ============================================================
# BASE64 HELPERS
# ============================================================

def _base64_encode(data: bytes) -> str:
    """
    Encode bytes using standard Base64.

    Standard Base64 is used consistently between the server
    and desktop client.
    """
    return base64.b64encode(data).decode("ascii")


def _base64_decode(value: str) -> bytes:
    """
    Decode a Base64 string into bytes.
    """
    return base64.b64decode(value.encode("ascii"), validate=True)


# ============================================================
# PRIVATE KEY LOADING
# ============================================================

def load_private_key() -> Ed25519PrivateKey:
    """
    Load the server's Ed25519 private key from the environment.

    Environment variable:
        OFFLINE_LICENSE_PRIVATE_KEY

    The value must be Base64 encoded raw Ed25519 private-key bytes.

    Raises:
        RuntimeError if the key is missing or invalid.
    """

    encoded_key = os.getenv(PRIVATE_KEY_ENV_NAME)

    if not encoded_key:
        raise RuntimeError(
            "OFFLINE_LICENSE_PRIVATE_KEY environment variable is not set."
        )

    encoded_key = encoded_key.strip()

    try:
        raw_key = _base64_decode(encoded_key)
    except Exception as error:
        raise RuntimeError(
            "OFFLINE_LICENSE_PRIVATE_KEY is not valid Base64."
        ) from error

    if len(raw_key) != 32:
        raise RuntimeError(
            "OFFLINE_LICENSE_PRIVATE_KEY must contain exactly "
            "32 decoded bytes for an Ed25519 private key."
        )

    try:
        return Ed25519PrivateKey.from_private_bytes(raw_key)
    except Exception as error:
        raise RuntimeError(
            "OFFLINE_LICENSE_PRIVATE_KEY contains an invalid "
            "Ed25519 private key."
        ) from error


# ============================================================
# PUBLIC KEY
# ============================================================

def get_public_key_bytes() -> bytes:
    """
    Derive the Ed25519 public key from the server private key.
    """
    private_key = load_private_key()

    return private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )


def get_public_key_base64() -> str:
    """
    Return the server's Ed25519 public key as Base64.

    This value can eventually be embedded into MultiPrint.exe.
    """
    return _base64_encode(get_public_key_bytes())


# ============================================================
# CANONICAL AUTHORIZATION SERIALIZATION
# ============================================================

def canonicalize_authorization(authorization: dict[str, Any]) -> bytes:
    """
    Convert an authorization dictionary into deterministic bytes.

    The exact same canonicalization must be used by the desktop
    application when verifying the signature.

    Rules:
    - UTF-8 encoding
    - JSON object keys sorted
    - compact JSON
    - no unnecessary whitespace
    - ensure_ascii=False
    """

    if not isinstance(authorization, dict):
        raise TypeError(
            "Authorization must be a dictionary."
        )

    try:
        serialized = json.dumps(
            authorization,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Authorization contains values that cannot be serialized."
        ) from error

    return serialized.encode("utf-8")


# ============================================================
# SIGN AUTHORIZATION
# ============================================================

def sign_authorization(
    authorization: dict[str, Any],
) -> str:
    """
    Sign an authorization dictionary using Ed25519.

    Returns:
        Base64-encoded Ed25519 signature.
    """

    payload = canonicalize_authorization(authorization)

    private_key = load_private_key()

    signature = private_key.sign(payload)

    return _base64_encode(signature)


# ============================================================
# SIGNATURE VERIFICATION
# ============================================================

def verify_authorization_signature(
    authorization: dict[str, Any],
    signature: str,
    public_key_base64: str | None = None,
) -> bool:
    """
    Verify an authorization signature.

    This helper is primarily useful for server-side tests.

    The desktop application will perform its own verification
    using the embedded public key.
    """

    if not isinstance(authorization, dict):
        return False

    if not isinstance(signature, str) or not signature:
        return False

    try:
        if public_key_base64 is None:
            public_key_base64 = get_public_key_base64()

        public_key_bytes = _base64_decode(
            public_key_base64.strip()
        )

        if len(public_key_bytes) != 32:
            return False

        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

        signature_bytes = _base64_decode(
            signature.strip()
        )

        payload = canonicalize_authorization(
            authorization
        )

        public_key.verify(
            signature_bytes,
            payload,
        )

        return True

    except Exception:
        return False


# ============================================================
# KEY INFORMATION
# ============================================================

def get_key_information() -> dict[str, str]:
    """
    Return non-secret information about the signing key.

    IMPORTANT:
    This function intentionally never returns the private key.
    """

    public_key = get_public_key_base64()

    return {
        "algorithm": "Ed25519",
        "public_key": public_key,
    }
"""
Generate the Ed25519 signing key pair for MultiPrint offline
authorizations.

IMPORTANT:
- Run this script when creating the signing key.
- The PRIVATE key must remain secret.
- The PRIVATE key goes into the server environment variable:
      OFFLINE_LICENSE_PRIVATE_KEY
- The PUBLIC key will eventually be embedded into MultiPrint.exe.
- Never put the private key into main.py or the desktop application.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

import base64


def base64_encode(data: bytes) -> str:
    """
    Convert bytes to standard Base64.
    """
    return base64.b64encode(data).decode("ascii")


def main():
    print()
    print("=" * 70)
    print("MultiPrint Offline Authorization - Ed25519 Key Generator")
    print("=" * 70)
    print()

    # --------------------------------------------------------
    # Generate a new Ed25519 key pair
    # --------------------------------------------------------

    private_key = Ed25519PrivateKey.generate()

    public_key = private_key.public_key()

    # --------------------------------------------------------
    # Export raw key bytes
    # --------------------------------------------------------

    private_key_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )

    public_key_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # --------------------------------------------------------
    # Encode for environment / application use
    # --------------------------------------------------------

    private_key_base64 = base64_encode(
        private_key_bytes
    )

    public_key_base64 = base64_encode(
        public_key_bytes
    )

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    print("ALGORITHM:")
    print("Ed25519")
    print()

    print("PRIVATE KEY")
    print("-" * 70)
    print(private_key_base64)
    print()

    print("PUBLIC KEY")
    print("-" * 70)
    print(public_key_base64)
    print()

    print("=" * 70)
    print("IMPORTANT SECURITY INSTRUCTIONS")
    print("=" * 70)
    print()
    print("1. Keep the PRIVATE KEY secret.")
    print()
    print(
        "2. Put the private key into the production server "
        "environment variable:"
    )
    print()
    print("   OFFLINE_LICENSE_PRIVATE_KEY")
    print()
    print(
        "3. NEVER put the private key inside MultiPrint.exe."
    )
    print()
    print(
        "4. The PUBLIC KEY is safe to embed inside MultiPrint.exe."
    )
    print()
    print(
        "5. If the private key is ever exposed, generate a new "
        "key pair and replace the server public key in the client."
    )
    print()
    print(
        "6. Save the private key somewhere secure before closing "
        "this window."
    )
    print()
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
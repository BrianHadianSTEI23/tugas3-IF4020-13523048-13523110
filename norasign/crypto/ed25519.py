"""
Ed25519 (PureEdDSA) per RFC 8032.
Profile: ed25519 (Tabel 2.1).
Signature format: standard 64-byte Ed25519 encoding.
Input: raw message bytes without pre-hashing.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from norasign.constants import SIG_LENGTH_ED25519


def sign_ed25519(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    """
    Sign message using PureEdDSA (Ed25519).
    Message is provided directly without pre-hashing.
    Returns 64 bytes signature.
    """
    signature = private_key.sign(message)
    if len(signature) != SIG_LENGTH_ED25519:
        raise ValueError(
            f"Expected Ed25519 signature length {SIG_LENGTH_ED25519} bytes, got {len(signature)}"
        )
    return signature


def verify_ed25519(
    public_key: ed25519.Ed25519PublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify Ed25519 signature over message.
    Returns True if valid, False otherwise.
    """
    if len(signature) != SIG_LENGTH_ED25519:
        return False

    try:
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False

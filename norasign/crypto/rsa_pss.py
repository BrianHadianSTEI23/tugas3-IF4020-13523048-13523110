"""
RSASSA-PSS with SHA-256 and MGF1-SHA-256, salt 32 bytes.
Profile: rsa-pss-sha256 (Tabel 2.1).
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from norasign.constants import SIG_LENGTH_RSA_PSS


def sign_rsa_pss(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """
    Sign message using RSASSA-PSS:
    - Hash: SHA-256
    - MGF: MGF1 with SHA-256
    - Salt length: 32 bytes
    Returns exactly 384 bytes signature.
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )
    if len(signature) != SIG_LENGTH_RSA_PSS:
        raise ValueError(
            f"Expected RSA signature length of {SIG_LENGTH_RSA_PSS} bytes, got {len(signature)}"
        )
    return signature


def verify_rsa_pss(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """
    Verify RSASSA-PSS signature over message.
    Returns True if valid, False otherwise.
    """
    if len(signature) != SIG_LENGTH_RSA_PSS:
        return False

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False

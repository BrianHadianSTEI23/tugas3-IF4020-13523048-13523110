"""
Cryptographic abstraction package for NoraSign.
IF4020 Kriptografi Semester 1 2026/2027.
"""

from typing import Union
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from norasign.constants import (
    ALG_RSA_PSS,
    ALG_ECDSA_P256,
    ALG_ED25519,
    SUPPORTED_ALGORITHMS,
)
from norasign.crypto.keys import (
    generate_keypair,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
    calculate_keyid,
    save_keypair_files,
)
from norasign.crypto.rsa_pss import sign_rsa_pss, verify_rsa_pss
from norasign.crypto.ecdsa_p256 import sign_ecdsa_p256, verify_ecdsa_p256
from norasign.crypto.ed25519 import sign_ed25519, verify_ed25519


def sign_message(
    private_key: Union[RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey],
    algorithm: str,
    message: bytes,
) -> bytes:
    """
    Sign raw message bytes according to the specified algorithm profile.
    """
    if algorithm == ALG_RSA_PSS:
        if not isinstance(private_key, RSAPrivateKey):
            raise TypeError("Private key is not an RSA private key")
        return sign_rsa_pss(private_key, message)

    elif algorithm == ALG_ECDSA_P256:
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise TypeError("Private key is not an EllipticCurve private key")
        return sign_ecdsa_p256(private_key, message)

    elif algorithm == ALG_ED25519:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("Private key is not an Ed25519 private key")
        return sign_ed25519(private_key, message)

    else:
        raise ValueError(f"Unsupported signature algorithm profile: {algorithm}")


def verify_message_signature(
    public_key: Union[RSAPublicKey, EllipticCurvePublicKey, Ed25519PublicKey],
    algorithm: str,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify raw signature bytes over message bytes according to algorithm profile.
    """
    if algorithm == ALG_RSA_PSS:
        if not isinstance(public_key, RSAPublicKey):
            return False
        return verify_rsa_pss(public_key, message, signature)

    elif algorithm == ALG_ECDSA_P256:
        if not isinstance(public_key, EllipticCurvePublicKey):
            return False
        return verify_ecdsa_p256(public_key, message, signature)

    elif algorithm == ALG_ED25519:
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        return verify_ed25519(public_key, message, signature)

    else:
        return False


__all__ = [
    "generate_keypair",
    "export_private_key_pem",
    "export_public_key_pem",
    "load_private_key_pem",
    "load_public_key_pem",
    "calculate_keyid",
    "save_keypair_files",
    "sign_message",
    "verify_message_signature",
    "sign_rsa_pss",
    "verify_rsa_pss",
    "sign_ecdsa_p256",
    "verify_ecdsa_p256",
    "sign_ed25519",
    "verify_ed25519",
]

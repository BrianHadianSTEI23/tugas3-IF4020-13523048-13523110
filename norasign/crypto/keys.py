"""
Key generation, serialization, and fingerprint calculation.
Adheres to Table 2.1 and Table 2.5 of IF4020 Tugas 3.
"""

import hashlib
import os
from typing import Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from norasign.constants import (
    ALG_RSA_PSS,
    ALG_ECDSA_P256,
    ALG_ED25519,
    SUPPORTED_ALGORITHMS,
)

# SECP256R1 curve order n
SECP256R1_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def calculate_keyid(public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey]) -> str:
    """
    Calculate public key fingerprint (keyid) according to Table 2.5:
    keyid = hex_lower(SHA256(DER_SPKI))
    where DER_SPKI is SubjectPublicKeyInfo exported in DER format.
    """
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest().lower()


def generate_keypair(algorithm: str) -> Tuple[
    Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey],
    Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey],
]:
    """
    Generate a cryptographic keypair matching the profile:
    - rsa-pss-sha256: RSA 3072-bit, e=65537
    - ecdsa-p256-sha256: NIST P-256 / secp256r1
    - ed25519: RFC 8032 Ed25519
    """
    if algorithm == ALG_RSA_PSS:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
    elif algorithm == ALG_ECDSA_P256:
        private_key = ec.generate_private_key(
            curve=ec.SECP256R1(),
        )
    elif algorithm == ALG_ED25519:
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported algorithm for key generation: {algorithm}")

    return private_key, private_key.public_key()


def export_private_key_pem(
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]
) -> bytes:
    """
    Export private key as unencrypted PKCS#8 in PEM format (label PRIVATE KEY).
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def export_public_key_pem(
    public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey]
) -> bytes:
    """
    Export public key as SubjectPublicKeyInfo (SPKI) in PEM format (label PUBLIC KEY).
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(
    pem_bytes: bytes,
) -> Tuple[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey], str]:
    """
    Load private key from PKCS#8 PEM and determine algorithm profile.
    Validates key parameters:
    - RSA: 3072 bits, e=65537
    - ECDSA: SECP256R1
    - Ed25519: Ed25519
    Returns (private_key_object, algorithm_name).
    """
    try:
        key = serialization.load_pem_private_key(pem_bytes, password=None)
    except Exception as e:
        raise ValueError(f"Failed to parse private key PEM: {e}")

    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size != 3072:
            raise ValueError(f"RSA key size must be 3072 bits, found {key.key_size} bits")
        if key.public_key().public_numbers().e != 65537:
            raise ValueError(f"RSA public exponent must be 65537, found {key.public_key().public_numbers().e}")
        return key, ALG_RSA_PSS

    if isinstance(key, ec.EllipticCurvePrivateKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError(f"ECDSA curve must be NIST P-256 (SECP256R1), found {key.curve.name}")
        return key, ALG_ECDSA_P256

    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key, ALG_ED25519

    raise ValueError(f"Unsupported private key type: {type(key).__name__}")


def load_public_key_pem(
    pem_bytes: bytes,
) -> Tuple[Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey], str, str]:
    """
    Load public key from SPKI PEM, determine algorithm profile, and calculate keyid.
    Validates key parameters.
    Returns (public_key_object, algorithm_name, keyid).
    """
    try:
        key = serialization.load_pem_public_key(pem_bytes)
    except Exception as e:
        raise ValueError(f"Failed to parse public key PEM: {e}")

    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size != 3072:
            raise ValueError(f"RSA key size must be 3072 bits, found {key.key_size} bits")
        if key.public_numbers().e != 65537:
            raise ValueError(f"RSA public exponent must be 65537, found {key.public_numbers().e}")
        algo = ALG_RSA_PSS

    elif isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError(f"ECDSA curve must be NIST P-256 (SECP256R1), found {key.curve.name}")
        algo = ALG_ECDSA_P256

    elif isinstance(key, ed25519.Ed25519PublicKey):
        algo = ALG_ED25519

    else:
        raise ValueError(f"Unsupported public key type: {type(key).__name__}")

    keyid = calculate_keyid(key)
    return key, algo, keyid


def save_keypair_files(
    algorithm: str,
    out_prefix: str,
    overwrite: bool = False,
) -> Tuple[str, str, str]:
    """
    Generate and save keypair to <out_prefix>.key.pem and <out_prefix>.pub.pem.
    Requires explicit overwrite flag if private key file already exists.
    Returns (key_path, pub_path, keyid).
    """
    priv_path = f"{out_prefix}.key.pem"
    pub_path = f"{out_prefix}.pub.pem"

    if os.path.exists(priv_path) and not overwrite:
        raise FileExistsError(
            f"Private key file '{priv_path}' already exists. Overwrite requires explicit option."
        )

    # Ensure parent directory exists
    parent_dir = os.path.dirname(out_prefix)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    priv_key, pub_key = generate_keypair(algorithm)
    priv_pem = export_private_key_pem(priv_key)
    pub_pem = export_public_key_pem(pub_key)
    keyid = calculate_keyid(pub_key)

    # Write private key with restrictive permissions (0o600)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    fd = os.open(priv_path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(priv_pem)
    except Exception:
        if os.path.exists(priv_path):
            os.remove(priv_path)
        raise

    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    return priv_path, pub_path, keyid

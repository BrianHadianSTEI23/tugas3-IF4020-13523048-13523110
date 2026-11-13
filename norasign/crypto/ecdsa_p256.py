"""
ECDSA P-256 with SHA-256.
Profile: ecdsa-p256-sha256 (Tabel 2.1).
Signature format: raw r || s (64 bytes, 32 bytes each big-endian).
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from norasign.constants import SIG_LENGTH_ECDSA_P256
from norasign.crypto.keys import SECP256R1_ORDER


def der_to_raw_rs(der_sig: bytes) -> bytes:
    """
    Convert ASN.1 DER ECDSA signature to 64-byte raw r || s.
    Each value is 32 bytes big-endian.
    """
    r, s = utils.decode_dss_signature(der_sig)
    return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")


def raw_rs_to_der(raw_sig: bytes) -> bytes:
    """
    Convert 64-byte raw r || s signature to ASN.1 DER format.
    Checks that r and s are within [1, n-1].
    Raises ValueError if raw_sig is not 64 bytes or if r, s are out of domain.
    """
    if len(raw_sig) != SIG_LENGTH_ECDSA_P256:
        raise ValueError(
            f"Expected ECDSA raw signature length {SIG_LENGTH_ECDSA_P256} bytes, got {len(raw_sig)}"
        )

    r = int.from_bytes(raw_sig[:32], byteorder="big")
    s = int.from_bytes(raw_sig[32:], byteorder="big")

    if not (1 <= r < SECP256R1_ORDER) or not (1 <= s < SECP256R1_ORDER):
        raise ValueError("ECDSA (r, s) values are outside the valid curve order domain [1, n-1]")

    return utils.encode_dss_signature(r, s)


def sign_ecdsa_p256(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """
    Sign message using ECDSA with SHA-256 and P-256 curve.
    Converts ASN.1 DER output to 64-byte raw r || s format.
    """
    der_sig = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256()),
    )
    raw_sig = der_to_raw_rs(der_sig)
    if len(raw_sig) != SIG_LENGTH_ECDSA_P256:
        raise ValueError(
            f"Expected ECDSA raw signature length {SIG_LENGTH_ECDSA_P256} bytes, got {len(raw_sig)}"
        )
    return raw_sig


def verify_ecdsa_p256(
    public_key: ec.EllipticCurvePublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify ECDSA raw 64-byte r || s signature over message.
    Returns True if valid, False otherwise.
    """
    if len(signature) != SIG_LENGTH_ECDSA_P256:
        return False

    try:
        der_sig = raw_rs_to_der(signature)
        public_key.verify(
            der_sig,
            message,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError):
        return False

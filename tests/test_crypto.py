"""
Unit tests for cryptographic engine in norasign.crypto.
IF4020 Kriptografi Chapter 3.
"""

import hashlib
import os
import tempfile
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from norasign.constants import (
    ALG_RSA_PSS,
    ALG_ECDSA_P256,
    ALG_ED25519,
    SIG_LENGTH_RSA_PSS,
    SIG_LENGTH_ECDSA_P256,
    SIG_LENGTH_ED25519,
)
from norasign.crypto import (
    generate_keypair,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
    calculate_keyid,
    save_keypair_files,
    sign_message,
    verify_message_signature,
    sign_rsa_pss,
    verify_rsa_pss,
    sign_ecdsa_p256,
    verify_ecdsa_p256,
    sign_ed25519,
    verify_ed25519,
)
from norasign.crypto.ecdsa_p256 import der_to_raw_rs, raw_rs_to_der


def test_rsa_pss_keygen_and_fingerprint():
    priv, pub = generate_keypair(ALG_RSA_PSS)
    assert isinstance(priv, rsa.RSAPrivateKey)
    assert priv.key_size == 3072
    assert pub.public_numbers().e == 65537

    spki_der = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected_fp = hashlib.sha256(spki_der).hexdigest().lower()
    assert calculate_keyid(pub) == expected_fp


def test_ecdsa_p256_keygen_and_fingerprint():
    priv, pub = generate_keypair(ALG_ECDSA_P256)
    assert isinstance(priv, ec.EllipticCurvePrivateKey)
    assert isinstance(priv.curve, ec.SECP256R1)

    spki_der = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected_fp = hashlib.sha256(spki_der).hexdigest().lower()
    assert calculate_keyid(pub) == expected_fp


def test_ed25519_keygen_and_fingerprint():
    priv, pub = generate_keypair(ALG_ED25519)
    assert isinstance(priv, ed25519.Ed25519PrivateKey)

    spki_der = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected_fp = hashlib.sha256(spki_der).hexdigest().lower()
    assert calculate_keyid(pub) == expected_fp


def test_pem_roundtrip_and_parameter_validation():
    for algo in [ALG_RSA_PSS, ALG_ECDSA_P256, ALG_ED25519]:
        priv, pub = generate_keypair(algo)
        priv_pem = export_private_key_pem(priv)
        pub_pem = export_public_key_pem(pub)

        assert b"BEGIN PRIVATE KEY" in priv_pem
        assert b"BEGIN PUBLIC KEY" in pub_pem

        loaded_priv, loaded_algo = load_private_key_pem(priv_pem)
        assert loaded_algo == algo

        loaded_pub, loaded_pub_algo, keyid = load_public_key_pem(pub_pem)
        assert loaded_pub_algo == algo
        assert keyid == calculate_keyid(pub)


def test_rsa_pss_sign_and_verify():
    priv, pub = generate_keypair(ALG_RSA_PSS)
    msg = b"Manifest message content for NoraSign RSA"

    sig = sign_rsa_pss(priv, msg)
    assert len(sig) == SIG_LENGTH_RSA_PSS
    assert verify_rsa_pss(pub, msg, sig) is True

    # Tampered message fails
    assert verify_rsa_pss(pub, msg + b"!", sig) is False

    # Tampered signature fails
    corrupt_sig = bytearray(sig)
    corrupt_sig[10] ^= 0x01
    assert verify_rsa_pss(pub, msg, bytes(corrupt_sig)) is False


def test_ecdsa_p256_sign_and_verify():
    priv, pub = generate_keypair(ALG_ECDSA_P256)
    msg = b"Manifest message content for NoraSign ECDSA"

    sig = sign_ecdsa_p256(priv, msg)
    assert len(sig) == SIG_LENGTH_ECDSA_P256
    assert verify_ecdsa_p256(pub, msg, sig) is True

    # Tampered message fails
    assert verify_ecdsa_p256(pub, msg + b"x", sig) is False

    # Tampered signature fails
    corrupt_sig = bytearray(sig)
    corrupt_sig[5] ^= 0x01
    assert verify_ecdsa_p256(pub, msg, bytes(corrupt_sig)) is False


def test_ecdsa_raw_rs_conversion():
    # Test valid conversion
    r = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
    s = 0x0FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA987654321
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert len(raw) == 64
    der = raw_rs_to_der(raw)
    raw_rec = der_to_raw_rs(der)
    assert raw_rec == raw

    # Test out-of-domain r or s
    zero_r = (0).to_bytes(32, "big") + s.to_bytes(32, "big")
    with pytest.raises(ValueError, match="outside the valid curve order"):
        raw_rs_to_der(zero_r)


def test_ed25519_sign_and_verify():
    priv, pub = generate_keypair(ALG_ED25519)
    msg = b"Manifest message content for NoraSign Ed25519"

    sig = sign_ed25519(priv, msg)
    assert len(sig) == SIG_LENGTH_ED25519
    assert verify_ed25519(pub, msg, sig) is True

    # Tampered message fails
    assert verify_ed25519(pub, msg + b"_", sig) is False

    # Tampered signature fails
    corrupt_sig = bytearray(sig)
    corrupt_sig[0] ^= 0xFF
    assert verify_ed25519(pub, msg, bytes(corrupt_sig)) is False


def test_save_keypair_files_and_overwrite():
    with tempfile.TemporaryDirectory() as tmpdir:
        prefix = os.path.join(tmpdir, "test_key")
        k_path, p_path, keyid = save_keypair_files(ALG_ED25519, prefix, overwrite=False)
        assert os.path.exists(k_path)
        assert os.path.exists(p_path)

        # Attempting overwrite without force raises FileExistsError
        with pytest.raises(FileExistsError):
            save_keypair_files(ALG_ED25519, prefix, overwrite=False)

        # Overwrite with force succeeds
        save_keypair_files(ALG_ED25519, prefix, overwrite=True)

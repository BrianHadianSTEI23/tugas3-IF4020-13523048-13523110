"""
Tests for Table 2.11 minimum scenarios related to Signing and Manifests.
IF4020 Kriptografi Chapter 3 - Section 2.8 and Table 2.11.
"""

import base64
import json
import os
import tempfile
import pytest

from norasign.bundle import create_bundle, parse_and_validate_bundle, serialize_bundle
from norasign.constants import (
    ALG_ECDSA_P256,
    ALG_ED25519,
    ALG_RSA_PSS,
)
from norasign.crypto import (
    generate_keypair,
    load_private_key_pem,
    load_public_key_pem,
    save_keypair_files,
    sign_message,
    verify_message_signature,
)
from norasign.manifest import (
    build_manifest,
    parse_and_validate_manifest,
    serialize_manifest,
)


def test_scenario_u01_text_binary_empty_files_all_algorithms():
    """
    U01: Tandatangani berkas teks, berkas biner, serta berkas kosong
    menggunakan kunci dan metadata yang sesuai pada ketiga algoritma.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create 3 types of files
        text_file = os.path.join(tmpdir, "doc.txt")
        with open(text_file, "wb") as f:
            f.write("Line 1\nLine 2\nUTF-8 sample: 1234".encode("utf-8"))

        bin_file = os.path.join(tmpdir, "program.bin")
        with open(bin_file, "wb") as f:
            f.write(os.urandom(65536)) # 64 KB random binary

        empty_file = os.path.join(tmpdir, "empty.dat")
        with open(empty_file, "wb") as f:
            f.write(b"") # 0 bytes

        files = [("doc.txt", text_file), ("program.bin", bin_file), ("empty.dat", empty_file)]

        for algo in [ALG_RSA_PSS, ALG_ECDSA_P256, ALG_ED25519]:
            prefix = os.path.join(tmpdir, f"u01_key_{algo}")
            k_path, p_path, keyid = save_keypair_files(algo, prefix)

            with open(k_path, "rb") as f:
                priv_key, _ = load_private_key_pem(f.read())
            with open(p_path, "rb") as f:
                pub_key, _, _ = load_public_key_pem(f.read())

            for fname, fpath in files:
                m_dict, m_bytes = build_manifest(
                    artifact_path=fpath,
                    package="test-suite-pkg",
                    version="1.0.0",
                    algorithm=algo,
                    keyid=keyid,
                )
                sig = sign_message(priv_key, algo, m_bytes)
                bundle_dict = create_bundle(m_bytes, sig)
                bundle_bytes = serialize_bundle(bundle_dict)

                # Parse bundle and verify signature
                m_parsed, s_parsed, _ = parse_and_validate_bundle(bundle_bytes)
                assert m_parsed == m_bytes
                assert s_parsed == sig
                assert verify_message_signature(pub_key, algo, m_parsed, s_parsed) is True


def test_scenario_u04_manifest_version_tamper_invalidates_signature():
    """
    U04: Ubah versi pada manifest dan pertahankan aturan serialisasinya.
    Gunakan tanda tangan dari manifest sebelum diubah.
    Verifikasi tanda tangan harus gagal (INVALID_SIGNATURE).
    """
    priv, pub = generate_keypair(ALG_ED25519)
    keyid = "d" * 64

    # Original manifest
    m1 = {
        "schema": "minisign-manifest/v1",
        "package": "app",
        "version": "1.0.0",
        "algorithm": ALG_ED25519,
        "keyid": keyid,
        "artifact": {"name": "app.bin", "size": 100, "sha256": "e" * 64},
    }
    m1_bytes = serialize_manifest(m1)
    sig1 = sign_message(priv, ALG_ED25519, m1_bytes)
    assert verify_message_signature(pub, ALG_ED25519, m1_bytes, sig1) is True

    # Tampered manifest with version 1.0.1 (retaining canonical serialization)
    m2 = dict(m1)
    m2["version"] = "1.0.1"
    m2_bytes = serialize_manifest(m2)

    # Verifying original signature on modified manifest MUST FAIL
    assert verify_message_signature(pub, ALG_ED25519, m2_bytes, sig1) is False


def test_scenario_u05_signature_single_bit_flip():
    """
    U05: Ubah satu bit tanda tangan. Pertahankan panjang tanda tangan
    dan gunakan encoding Base64 yang valid.
    Verifikasi harus gagal.
    """
    priv, pub = generate_keypair(ALG_ECDSA_P256)
    msg = b"Manifest message"
    sig = sign_message(priv, ALG_ECDSA_P256, msg)
    assert verify_message_signature(pub, ALG_ECDSA_P256, msg, sig) is True

    # Flip 1 bit in signature
    corrupt_sig = bytearray(sig)
    corrupt_sig[0] ^= 0x01
    corrupt_sig = bytes(corrupt_sig)

    assert len(corrupt_sig) == len(sig)
    # Ensure Base64 encoding remains valid
    b64_str = base64.b64encode(corrupt_sig).decode("ascii")
    decoded = base64.b64decode(b64_str)
    assert decoded == corrupt_sig

    assert verify_message_signature(pub, ALG_ECDSA_P256, msg, corrupt_sig) is False


def test_scenario_u13_bundle_whitespace_and_field_order_tolerance():
    """
    U13: Ubah white space dan urutan field pada JSON bundle.
    Pertahankan kedua string Base64 tanpa perubahan.
    Bundle harus tetap terbaca dan manifest/signature tetap valid.
    """
    manifest_bytes = b'{"schema":"minisign-manifest/v1"}'
    sig_bytes = b"\x12" * 64

    m_b64 = base64.b64encode(manifest_bytes).decode("ascii")
    s_b64 = base64.b64encode(sig_bytes).decode("ascii")

    # Reorder fields: signature_b64 first, then schema, then manifest_b64, with extra indentation & newlines
    custom_bundle_json = f"""
    {{
        "signature_b64":  "{s_b64}",
        "schema":  "minisign-bundle/v1",
        "manifest_b64":  "{m_b64}"
    }}
    """.encode("utf-8")

    m_out, s_out, parsed = parse_and_validate_bundle(custom_bundle_json)
    assert m_out == manifest_bytes
    assert s_out == sig_bytes


def test_scenario_u14_identical_manifest_signing_determinism_vs_randomness():
    """
    U14: Tandatangani manifest yang identik sebanyak dua kali menggunakan
    kunci yang sama. Bandingkan kedua tanda tangan:
    - RSA-PSS: Berbeda (karena random 32-byte salt). Kedua tanda tangan valid.
    - Ed25519: Identik (deterministik per RFC 8032). Kedua tanda tangan valid.
    - ECDSA: Baik identik (RFC 6979) maupun acak (CSPRNG), kedua tanda tangan valid.
    """
    msg = b'{"schema":"minisign-manifest/v1","package":"demo"}'

    # 1. RSA-PSS
    rsa_priv, rsa_pub = generate_keypair(ALG_RSA_PSS)
    rsa_sig1 = sign_message(rsa_priv, ALG_RSA_PSS, msg)
    rsa_sig2 = sign_message(rsa_priv, ALG_RSA_PSS, msg)
    # Salt is randomized, so signatures must be distinct
    assert rsa_sig1 != rsa_sig2
    assert verify_message_signature(rsa_pub, ALG_RSA_PSS, msg, rsa_sig1) is True
    assert verify_message_signature(rsa_pub, ALG_RSA_PSS, msg, rsa_sig2) is True

    # 2. Ed25519
    ed_priv, ed_pub = generate_keypair(ALG_ED25519)
    ed_sig1 = sign_message(ed_priv, ALG_ED25519, msg)
    ed_sig2 = sign_message(ed_priv, ALG_ED25519, msg)
    # PureEdDSA is deterministic, so signatures must be identical
    assert ed_sig1 == ed_sig2
    assert verify_message_signature(ed_pub, ALG_ED25519, msg, ed_sig1) is True
    assert verify_message_signature(ed_pub, ALG_ED25519, msg, ed_sig2) is True

    # 3. ECDSA
    ec_priv, ec_pub = generate_keypair(ALG_ECDSA_P256)
    ec_sig1 = sign_message(ec_priv, ALG_ECDSA_P256, msg)
    ec_sig2 = sign_message(ec_priv, ALG_ECDSA_P256, msg)
    assert verify_message_signature(ec_pub, ALG_ECDSA_P256, msg, ec_sig1) is True
    assert verify_message_signature(ec_pub, ALG_ECDSA_P256, msg, ec_sig2) is True

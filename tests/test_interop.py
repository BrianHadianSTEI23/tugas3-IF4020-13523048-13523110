"""
Interoperability tests with OpenSSL CLI.
IF4020 Kriptografi Chapter 3 - Section 2.8.
"""

import os
import shutil
import subprocess
import tempfile
import pytest

from norasign.constants import (
    ALG_ECDSA_P256,
    ALG_ED25519,
    ALG_RSA_PSS,
)
from norasign.crypto import (
    export_public_key_pem,
    generate_keypair,
    sign_message,
)
from norasign.crypto.ecdsa_p256 import raw_rs_to_der

OPENSSL_AVAILABLE = shutil.which("openssl") is not None


@pytest.mark.skipif(not OPENSSL_AVAILABLE, reason="OpenSSL CLI not installed on system")
def test_rsa_pss_interop_openssl():
    """
    Verify NoraSign RSA-PSS signature using OpenSSL dgst command.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        msg = b"Interop test message for RSA-PSS"
        msg_file = os.path.join(tmpdir, "msg.bin")
        with open(msg_file, "wb") as f:
            f.write(msg)

        priv, pub = generate_keypair(ALG_RSA_PSS)
        pub_file = os.path.join(tmpdir, "rsa.pub.pem")
        with open(pub_file, "wb") as f:
            f.write(export_public_key_pem(pub))

        sig = sign_message(priv, ALG_RSA_PSS, msg)
        sig_file = os.path.join(tmpdir, "rsa.sig")
        with open(sig_file, "wb") as f:
            f.write(sig)

        cmd = [
            "openssl", "dgst", "-sha256",
            "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:32",
            "-sigopt", "rsa_mgf1_md:sha256",
            "-verify", pub_file,
            "-signature", sig_file,
            msg_file,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0
        assert "Verified OK" in res.stdout


@pytest.mark.skipif(not OPENSSL_AVAILABLE, reason="OpenSSL CLI not installed on system")
def test_ecdsa_p256_interop_openssl():
    """
    Verify NoraSign ECDSA signature using OpenSSL dgst after converting raw r || s to ASN.1 DER.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        msg = b"Interop test message for ECDSA P-256"
        msg_file = os.path.join(tmpdir, "msg.bin")
        with open(msg_file, "wb") as f:
            f.write(msg)

        priv, pub = generate_keypair(ALG_ECDSA_P256)
        pub_file = os.path.join(tmpdir, "ec.pub.pem")
        with open(pub_file, "wb") as f:
            f.write(export_public_key_pem(pub))

        raw_sig = sign_message(priv, ALG_ECDSA_P256, msg)
        der_sig = raw_rs_to_der(raw_sig)
        sig_file = os.path.join(tmpdir, "ec.der.sig")
        with open(sig_file, "wb") as f:
            f.write(der_sig)

        cmd = [
            "openssl", "dgst", "-sha256",
            "-verify", pub_file,
            "-signature", sig_file,
            msg_file,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0
        assert "Verified OK" in res.stdout


@pytest.mark.skipif(not OPENSSL_AVAILABLE, reason="OpenSSL CLI not installed on system")
def test_ed25519_interop_openssl():
    """
    Verify NoraSign Ed25519 signature using OpenSSL pkeyutl -rawin.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        msg = b"Interop test message for Ed25519"
        msg_file = os.path.join(tmpdir, "msg.bin")
        with open(msg_file, "wb") as f:
            f.write(msg)

        priv, pub = generate_keypair(ALG_ED25519)
        pub_file = os.path.join(tmpdir, "ed.pub.pem")
        with open(pub_file, "wb") as f:
            f.write(export_public_key_pem(pub))

        sig = sign_message(priv, ALG_ED25519, msg)
        sig_file = os.path.join(tmpdir, "ed.sig")
        with open(sig_file, "wb") as f:
            f.write(sig)

        cmd = [
            "openssl", "pkeyutl", "-verify", "-rawin",
            "-pubin", "-inkey", pub_file,
            "-sigfile", sig_file,
            "-in", msg_file,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0
        assert "Signature Verified Successfully" in res.stdout

"""
Unit tests for CLI commands and error handling.
IF4020 Kriptografi Chapter 3 - Section 2.6 and Table 2.7.
"""

import os
import subprocess
import tempfile
import pytest

from norasign.constants import (
    ALG_ECDSA_P256,
    ALG_ED25519,
    ALG_RSA_PSS,
    EXIT_SUCCESS,
    EXIT_USAGE_OR_IO_ERROR,
)


def run_cli(*args):
    cmd = ["python3", "-m", "norasign.cli", *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def test_cli_help_and_version():
    res = run_cli("--version")
    assert res.returncode == EXIT_SUCCESS
    assert "norasign 1.0.0" in res.stdout

    res = run_cli("--help")
    assert res.returncode == EXIT_SUCCESS
    assert "keygen" in res.stdout
    assert "sign" in res.stdout


def test_cli_missing_required_args_exits_code_2():
    res = run_cli("sign")
    assert res.returncode == EXIT_USAGE_OR_IO_ERROR
    assert "error" in res.stderr.lower()


def test_cli_keygen_success_and_force():
    with tempfile.TemporaryDirectory() as tmpdir:
        prefix = os.path.join(tmpdir, "mykey")
        res = run_cli("keygen", "--algorithm", ALG_ED25519, "--out", prefix)
        assert res.returncode == EXIT_SUCCESS
        assert "Fingerprint:" in res.stdout
        assert os.path.exists(prefix + ".key.pem")
        assert os.path.exists(prefix + ".pub.pem")

        # Keygen without --force when file exists fails with exit code 2
        res2 = run_cli("keygen", "--algorithm", ALG_ED25519, "--out", prefix)
        assert res2.returncode == EXIT_USAGE_OR_IO_ERROR

        # Keygen with --force succeeds
        res3 = run_cli("keygen", "--algorithm", ALG_ED25519, "--out", prefix, "--force")
        assert res3.returncode == EXIT_SUCCESS


def test_cli_sign_missing_file_exits_code_2():
    with tempfile.TemporaryDirectory() as tmpdir:
        prefix = os.path.join(tmpdir, "signer")
        run_cli("keygen", "--algorithm", ALG_ED25519, "--out", prefix)

        res = run_cli(
            "sign",
            "--file", os.path.join(tmpdir, "nonexistent.bin"),
            "--package", "app",
            "--version", "1.0",
            "--key", prefix + ".key.pem",
            "--out", os.path.join(tmpdir, "bundle.json"),
        )
        assert res.returncode == EXIT_USAGE_OR_IO_ERROR
        assert "not found" in res.stderr.lower()


def test_cli_sign_all_three_algorithms():
    with tempfile.TemporaryDirectory() as tmpdir:
        for algo in [ALG_RSA_PSS, ALG_ECDSA_P256, ALG_ED25519]:
            prefix = os.path.join(tmpdir, f"signer_{algo}")
            run_cli("keygen", "--algorithm", algo, "--out", prefix)

            art_file = os.path.join(tmpdir, f"app_{algo}.bin")
            with open(art_file, "wb") as f:
                f.write(b"Production release binary content")

            out_bundle = os.path.join(tmpdir, f"{algo}.bundle.json")
            res = run_cli(
                "sign",
                "--file", art_file,
                "--package", "production-app",
                "--version", "1.0.0",
                "--key", prefix + ".key.pem",
                "--out", out_bundle,
            )
            assert res.returncode == EXIT_SUCCESS
            assert os.path.exists(out_bundle)

"""Verification pipeline tests (Section 2.7) and the full U01-U14 / SBOM scenario suite."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from norasign.cli import main as cli_main
from norasign.constants import ALG_ED25519
from norasign.verifier import run_verification

ROOT = Path(__file__).resolve().parent.parent
RESULT_FIELDS = ["valid", "status", "message", "algorithm", "keyid", "package", "version"]


@pytest.fixture
def release(tmp_path):
    prefix = str(tmp_path / "pub")
    assert cli_main(["keygen", "--algorithm", ALG_ED25519, "--out", prefix]) == 0
    art = tmp_path / "app.zip"
    art.write_bytes(b"payload")
    store = str(tmp_path / "trust.json")
    bundle = str(tmp_path / "release.json")
    assert cli_main(["trust", "add", "--key", prefix + ".pub.pem", "--package", "app", "--store", store]) == 0
    assert cli_main(["sign", "--file", str(art), "--package", "app", "--version", "1.0.0",
                     "--key", prefix + ".key.pem", "--out", bundle]) == 0
    return str(art), bundle, store


def test_ok_result_structure_and_json_output(release, capsys):
    art, bundle, store = release
    code = cli_main(["verify", "--file", art, "--bundle", bundle, "--trust-store", store,
                     "--package", "app", "--version", "1.0.0", "--json"])
    out = capsys.readouterr().out
    assert code == 0
    assert out.endswith("}\n") and out.count("\n") == 1
    res = json.loads(out)
    assert list(res.keys()) == RESULT_FIELDS
    assert res["valid"] is True and res["status"] == "OK" and res["algorithm"] == ALG_ED25519


def test_missing_option_reports_input_error_json(capsys):
    code = cli_main(["verify", "--json"])
    res = json.loads(capsys.readouterr().out)
    assert code == 2 and res["status"] == "INPUT_ERROR" and res["valid"] is False
    assert res["algorithm"] is None and res["keyid"] is None


def test_unreadable_bundle_is_input_error(release):
    art, _, store = release
    res = run_verification(art, os.path.dirname(art), store, "app", "1.0.0")
    assert res["status"] == "INPUT_ERROR"


def test_failure_keeps_metadata_but_not_valid(release):
    art, bundle, store = release
    res = run_verification(art, bundle, store, "app", "9.9.9")
    assert res["status"] == "METADATA_MISMATCH" and res["valid"] is False
    assert res["version"] == "1.0.0"


def test_verify_does_not_modify_artifact(release):
    art, bundle, store = release
    before = (open(art, "rb").read(), os.stat(art).st_mtime_ns)
    run_verification(art, bundle, store, "app", "1.0.0")
    assert (open(art, "rb").read(), os.stat(art).st_mtime_ns) == before


def test_bundle_over_64k_is_format_error(release, tmp_path):
    art, bundle, store = release
    big = tmp_path / "big.json"
    doc = json.load(open(bundle))
    big.write_text(json.dumps(doc) + " " * (64 * 1024))
    assert run_verification(art, str(big), store, "app", "1.0.0")["status"] == "FORMAT_ERROR"


def test_bundle_extra_field_and_bom(release, tmp_path):
    art, bundle, store = release
    doc = json.load(open(bundle))
    doc["public_key"] = "x"
    p = tmp_path / "extra.json"
    p.write_text(json.dumps(doc))
    assert run_verification(art, str(p), store, "app", "1.0.0")["status"] == "FORMAT_ERROR"
    p.write_bytes(b"\xef\xbb\xbf" + open(bundle, "rb").read())
    assert run_verification(art, str(p), store, "app", "1.0.0")["status"] == "FORMAT_ERROR"


def test_full_scenario_suite(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_scenarios.py"), "--out", str(tmp_path / "cases")],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    summary = json.load(open(tmp_path / "cases" / "results.json"))
    assert summary["passed"] == summary["total"]
    ids = {r["id"] for r in summary["results"]}
    assert {f"U{i:02d}" for i in range(1, 15)} <= ids
    assert summary["u14"]["ed25519"]["signature_identical"] is True
    assert summary["u14"]["rsa-pss-sha256"]["signature_identical"] is False

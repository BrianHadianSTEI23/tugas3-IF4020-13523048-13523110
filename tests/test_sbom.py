"""Signed SBOM tests (Bonus 3)."""

import io
import json
import zipfile

import pytest

from norasign.cli import main as cli_main
from norasign.constants import ALG_ECDSA_P256
from norasign.sbom import SbomFormatError, build_sbom, parse_sbom, verify_sbom


@pytest.fixture
def signed_release(tmp_path):
    prefix = str(tmp_path / "pub")
    cli_main(["keygen", "--algorithm", ALG_ECDSA_P256, "--out", prefix])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("bin/app", b"binary")
        zf.writestr("README", b"readme")
    art = tmp_path / "app.zip"
    art.write_bytes(buf.getvalue())
    store = str(tmp_path / "trust.json")
    cli_main(["trust", "add", "--key", prefix + ".pub.pem", "--package", "app", "--store", store])
    bundle = str(tmp_path / "app.bundle.json")
    cli_main(["sign", "--file", str(art), "--package", "app", "--version", "2.0", "--key", prefix + ".key.pem",
              "--out", bundle])
    sbom = str(tmp_path / "app.sbom.json")
    assert cli_main(["sbom", "generate", "--artifact", str(art), "--package", "app", "--version", "2.0",
                     "--component", "cryptography@46.0.0", "--out", sbom]) == 0
    sbom_bundle = str(tmp_path / "app.sbom.bundle.json")
    assert cli_main(["sbom", "sign", "--sbom", sbom, "--key", prefix + ".key.pem", "--out", sbom_bundle]) == 0
    return dict(art=str(art), bundle=bundle, sbom=sbom, sbom_bundle=sbom_bundle, store=store, key=prefix + ".key.pem")


def _verify(r, **over):
    args = dict(artifact_path=r["art"], artifact_bundle_path=r["bundle"], sbom_path=r["sbom"],
                sbom_bundle_path=r["sbom_bundle"], trust_store_path=r["store"], package="app", version="2.0")
    args.update(over)
    return verify_sbom(**args, emit=False)


def test_generate_lists_archive_members_and_components(signed_release):
    doc = json.load(open(signed_release["sbom"]))
    names = {c["name"] for c in doc["components"]}
    assert {"bin/app", "README", "cryptography"} <= names
    info = parse_sbom(open(signed_release["sbom"], "rb").read())
    assert info["artifact_name"] == "app.zip" and info["package"] == "app"


def test_valid_sbom(signed_release):
    res = _verify(signed_release)
    assert res["status"] == "OK" and res["exit_code"] == 0
    assert res["binding"]["sbom_artifact_sha256"] == res["binding"]["release_artifact_sha256"]


def test_tampered_sbom_content(signed_release):
    doc = json.load(open(signed_release["sbom"]))
    doc["components"] = []
    open(signed_release["sbom"], "w").write(json.dumps(doc, indent=2) + "\n")
    res = _verify(signed_release)
    assert res["stage"] == "sbom" and res["exit_code"] == 1


def test_replaced_artifact(signed_release):
    open(signed_release["art"], "wb").write(b"evil")
    res = _verify(signed_release)
    assert res["stage"] == "release" and res["status"] == "ARTIFACT_MISMATCH"


def test_resigned_artifact_with_stale_sbom(signed_release):
    open(signed_release["art"], "wb").write(b"new release")
    cli_main(["sign", "--file", signed_release["art"], "--package", "app", "--version", "2.0",
              "--key", signed_release["key"], "--out", signed_release["bundle"]])
    res = _verify(signed_release)
    assert res["status"] == "SBOM_BINDING_MISMATCH" and res["exit_code"] == 1


def test_missing_sbom_file_is_input_error(signed_release, tmp_path):
    res = _verify(signed_release, sbom_path=str(tmp_path / "none.json"))
    assert res["status"] == "INPUT_ERROR" and res["exit_code"] == 2


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(bomFormat="SPDX"),
        lambda d: d["metadata"]["component"]["hashes"].append({"alg": "SHA-256", "content": "0" * 64}),
        lambda d: d["metadata"]["component"].update(hashes=[]),
        lambda d: d["metadata"]["component"].update(properties=[]),
        lambda d: d.pop("components"),
    ],
)
def test_parse_rejects_bad_sbom(tmp_path, mutate):
    art = tmp_path / "a.bin"
    art.write_bytes(b"x")
    doc = json.loads(json.dumps(build_sbom(str(art), "app", "1.0")))
    mutate(doc)
    with pytest.raises(SbomFormatError):
        parse_sbom(json.dumps(doc).encode())


def test_parse_rejects_duplicate_keys():
    with pytest.raises(SbomFormatError):
        parse_sbom(b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}')

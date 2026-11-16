"""Unit tests for trust store management (Section 2.5, Table 2.6)."""

import base64
import json
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from norasign.constants import ALG_ECDSA_P256, ALG_ED25519, ALG_RSA_PSS
from norasign.crypto import save_keypair_files
from norasign import trust as trust_mod
from norasign.trust import (
    KeyNotTrustedError,
    TrustEntryNotFound,
    TrustStoreError,
    find_trusted_key,
    load_trust_store,
    parse_public_key_strict,
    trust_add,
    trust_list,
    trust_remove,
)


@pytest.fixture
def keys(tmp_path):
    out = {}
    for algo in (ALG_RSA_PSS, ALG_ECDSA_P256, ALG_ED25519):
        _, pub, keyid = save_keypair_files(algo, str(tmp_path / algo))
        out[algo] = (pub, keyid)
    return out


def test_add_creates_store_and_is_idempotent(tmp_path, keys):
    store = str(tmp_path / "trust.json")
    pub, keyid = keys[ALG_ED25519]
    r1 = trust_add(pub, "app", store, quiet=True)
    assert r1["action"] == "added" and r1["keyid"] == keyid
    before = open(store, "rb").read()
    r2 = trust_add(pub, "app", store, quiet=True)
    assert r2["action"] == "unchanged"
    assert open(store, "rb").read() == before
    r3 = trust_add(pub, "other", store, quiet=True)
    assert r3["action"] == "updated" and r3["packages"] == ["app", "other"]
    entries = load_trust_store(store)
    assert len(entries) == 1 and entries[0]["packages"] == ["app", "other"]


def test_add_prints_fingerprint_algorithm_packages(tmp_path, keys, capsys):
    store = str(tmp_path / "trust.json")
    pub, keyid = keys[ALG_RSA_PSS]
    trust_add(pub, "app", store)
    out = capsys.readouterr().out
    assert keyid in out and ALG_RSA_PSS in out and "app" in out


def test_add_rejects_wildcard_and_private_key(tmp_path, keys):
    store = str(tmp_path / "trust.json")
    pub, _ = keys[ALG_ED25519]
    with pytest.raises(TrustStoreError):
        trust_add(pub, "*", store, quiet=True)
    with pytest.raises(TrustStoreError):
        trust_add(pub.replace(".pub.pem", ".key.pem"), "app", store, quiet=True)
    assert not os.path.exists(store)


def test_list_and_remove(tmp_path, keys):
    store = str(tmp_path / "trust.json")
    for algo, (pub, _) in keys.items():
        trust_add(pub, "app", store, quiet=True)
    assert len(trust_list(store, quiet=True)) == 3
    keyid = keys[ALG_ECDSA_P256][1]
    trust_remove(keyid, store, quiet=True)
    assert keyid not in [e["keyid"] for e in trust_list(store, quiet=True)]
    with pytest.raises(TrustEntryNotFound):
        trust_remove(keyid, store, quiet=True)


def test_failed_write_keeps_previous_store(tmp_path, keys, monkeypatch):
    store = str(tmp_path / "trust.json")
    trust_add(keys[ALG_ED25519][0], "app", store, quiet=True)
    before = open(store, "rb").read()

    def boom(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(trust_mod.os, "replace", boom)
    with pytest.raises(trust_mod.TrustStoreIOError):
        trust_add(keys[ALG_RSA_PSS][0], "app", store, quiet=True)
    assert open(store, "rb").read() == before
    assert [f for f in os.listdir(tmp_path) if f.endswith(".tmp")] == []


def test_malformed_store_not_overwritten(tmp_path, keys):
    store = tmp_path / "trust.json"
    store.write_text('{"schema":"minisign-trust/v1","keys":[],"keys":[]}')
    with pytest.raises(TrustStoreError):
        trust_add(keys[ALG_ED25519][0], "app", str(store), quiet=True)
    assert store.read_text() == '{"schema":"minisign-trust/v1","keys":[],"keys":[]}'


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(extra=1),
        lambda d: d.update(schema="minisign-trust/v2"),
        lambda d: d["keys"][0].update(packages=[]),
        lambda d: d["keys"][0].update(packages=["app", "app"]),
        lambda d: d["keys"][0].update(packages="app"),
        lambda d: d["keys"][0].update(keyid=d["keyid_other"]),
        lambda d: d["keys"][0].update(algorithm="ed448"),
        lambda d: d["keys"][0].update(algorithm=ALG_RSA_PSS),
        lambda d: d["keys"][0].update(public_key_pem="/path/to/key.pem"),
        lambda d: d["keys"][0].pop("packages"),
        lambda d: d["keys"].append(dict(d["keys"][0])),
    ],
)
def test_parse_rejects_invalid_store(tmp_path, keys, mutate):
    store = str(tmp_path / "trust.json")
    trust_add(keys[ALG_ED25519][0], "app", store, quiet=True)
    doc = json.load(open(store))
    doc["keyid_other"] = keys[ALG_RSA_PSS][1]
    mutate(doc)
    other = doc.pop("keyid_other")
    assert other
    with pytest.raises(TrustStoreError):
        trust_mod.parse_trust_store(json.dumps(doc).encode())


def test_keyid_independent_of_pem_line_endings(keys):
    pub, keyid = keys[ALG_ECDSA_P256]
    pem = open(pub).read()
    body = "".join(pem.strip().splitlines()[1:-1])
    rewrapped = "-----BEGIN PUBLIC KEY-----\r\n" + "\r\n".join(body[i:i + 40] for i in range(0, len(body), 40)) + "\r\n-----END PUBLIC KEY-----\r\n"
    assert parse_public_key_strict(rewrapped)[2] == keyid


def test_rejects_wrong_parameters_and_compressed_point():
    rsa2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    pem = rsa2048.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with pytest.raises(TrustStoreError):
        parse_public_key_strict(pem)

    p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
    pem = p384.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with pytest.raises(TrustStoreError):
        parse_public_key_strict(pem)

    p256 = ec.generate_private_key(ec.SECP256R1()).public_key()
    compressed = p256.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    der_c = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200") + compressed
    pem_c = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der_c).decode() + "\n-----END PUBLIC KEY-----\n"
    with pytest.raises(TrustStoreError):
        parse_public_key_strict(pem_c)


def test_find_trusted_key_rules(tmp_path, keys):
    store = str(tmp_path / "trust.json")
    pub, keyid = keys[ALG_ED25519]
    trust_add(pub, "app", store, quiet=True)
    entries = load_trust_store(store)
    assert find_trusted_key(entries, keyid, ALG_ED25519, "app") is not None
    with pytest.raises(KeyNotTrustedError):
        find_trusted_key(entries, keyid, ALG_ECDSA_P256, "app")
    with pytest.raises(KeyNotTrustedError):
        find_trusted_key(entries, keyid, ALG_ED25519, "other")
    with pytest.raises(KeyNotTrustedError):
        find_trusted_key(entries, "0" * 64, ALG_ED25519, "app")
    with pytest.raises(KeyNotTrustedError):
        find_trusted_key([], keyid, ALG_ED25519, "app")

"""
Unit tests for manifest validation and canonical serialization.
IF4020 Kriptografi Chapter 3 - Section 2.3 and Table 2.3.
"""

import collections
import json
import os
import tempfile
import pytest

from norasign.constants import (
    ALG_ED25519,
    MAX_MANIFEST_BYTES,
    SCHEMA_MANIFEST,
)
from norasign.manifest import (
    build_manifest,
    parse_and_validate_manifest,
    serialize_manifest,
    strict_json_pairs_hook,
)


def get_valid_manifest_dict():
    return collections.OrderedDict([
        ("schema", SCHEMA_MANIFEST),
        ("package", "valid-app"),
        ("version", "1.0.0"),
        ("algorithm", ALG_ED25519),
        ("keyid", "a" * 64),
        ("artifact", collections.OrderedDict([
            ("name", "app.tar.gz"),
            ("size", 1024),
            ("sha256", "b" * 64),
        ])),
    ])


def test_canonical_manifest_serialization():
    m = get_valid_manifest_dict()
    canonical_bytes = serialize_manifest(m)

    # 1. UTF-8 without BOM
    assert not canonical_bytes.startswith(b"\xef\xbb\xbf")

    # 2. No whitespace outside strings
    assert b" " not in canonical_bytes
    assert b"\n" not in canonical_bytes
    assert b"\r" not in canonical_bytes
    assert b"\t" not in canonical_bytes

    # 3. Exact field ordering
    text = canonical_bytes.decode("utf-8")
    expected_prefix = '{"schema":"minisign-manifest/v1","package":"valid-app","version":"1.0.0","algorithm":"ed25519","keyid":"'
    assert text.startswith(expected_prefix)
    assert '"artifact":{"name":"app.tar.gz","size":1024,"sha256":' in text

    # 4. Strict parse roundtrip
    parsed = parse_and_validate_manifest(canonical_bytes, enforce_canonical=True)
    assert parsed["package"] == "valid-app"
    assert parsed["artifact"]["size"] == 1024


def test_reject_duplicate_fields():
    # Duplicate top-level key
    dup_json = b'{"schema":"minisign-manifest/v1","package":"app1","package":"app2","version":"1.0","algorithm":"ed25519","keyid":"' + (b"a"*64) + b'","artifact":{"name":"a","size":1,"sha256":"' + (b"b"*64) + b'"}}'
    with pytest.raises(ValueError, match="Duplicate field detected"):
        parse_and_validate_manifest(dup_json, enforce_canonical=False)

    # Duplicate nested key in artifact
    dup_nested = b'{"schema":"minisign-manifest/v1","package":"app1","version":"1.0","algorithm":"ed25519","keyid":"' + (b"a"*64) + b'","artifact":{"name":"a","name":"b","size":1,"sha256":"' + (b"b"*64) + b'"}}'
    with pytest.raises(ValueError, match="Duplicate field detected"):
        parse_and_validate_manifest(dup_nested, enforce_canonical=False)


def test_reject_null_values():
    null_json = b'{"schema":"minisign-manifest/v1","package":null,"version":"1.0.0","algorithm":"ed25519","keyid":"' + (b"a"*64) + b'","artifact":{"name":"app.bin","size":100,"sha256":"' + (b"b"*64) + b'"}}'
    with pytest.raises(ValueError, match="prohibited null value"):
        parse_and_validate_manifest(null_json, enforce_canonical=False)


def test_reject_extra_fields():
    extra_json = b'{"schema":"minisign-manifest/v1","package":"pkg","version":"1.0","algorithm":"ed25519","keyid":"' + (b"a"*64) + b'","artifact":{"name":"app.bin","size":100,"sha256":"' + (b"b"*64) + b'"},"extra":"forbidden"}'
    with pytest.raises(ValueError, match="Manifest fields must strictly be"):
        parse_and_validate_manifest(extra_json, enforce_canonical=False)


def test_reject_boolean_as_integer_size():
    # Table 2.3: "Nilai boolean tidak diterima sebagai integer"
    bool_size_json = b'{"schema":"minisign-manifest/v1","package":"pkg","version":"1.0","algorithm":"ed25519","keyid":"' + (b"a"*64) + b'","artifact":{"name":"app.bin","size":true,"sha256":"' + (b"b"*64) + b'"}}'
    with pytest.raises(ValueError, match="Artifact size must be an integer"):
        parse_and_validate_manifest(bool_size_json, enforce_canonical=False)


def test_reject_utf8_bom():
    m = get_valid_manifest_dict()
    canon = serialize_manifest(m)
    bom_manifest = b"\xef\xbb\xbf" + canon
    with pytest.raises(ValueError, match="UTF-8 BOM"):
        parse_and_validate_manifest(bom_manifest, enforce_canonical=False)


def test_reject_size_exceeding_16kib():
    m = get_valid_manifest_dict()
    # Artificial oversized manifest
    oversized = serialize_manifest(m) + (b" " * (MAX_MANIFEST_BYTES + 1))
    with pytest.raises(ValueError, match="exceeds maximum"):
        parse_and_validate_manifest(oversized, enforce_canonical=False)


def test_canonical_enforcement_detects_non_canonical_formatting():
    m = get_valid_manifest_dict()
    # Add non-canonical spaces
    non_canonical = json.dumps(m, indent=2).encode("utf-8")
    with pytest.raises(ValueError, match="Manifest bytes do not match canonical serialization"):
        parse_and_validate_manifest(non_canonical, enforce_canonical=True)


def test_build_manifest_from_artifact():
    with tempfile.TemporaryDirectory() as tmpdir:
        art_path = os.path.join(tmpdir, "release-archive.tar.gz")
        payload = b"Sample release payload binary data"
        with open(art_path, "wb") as f:
            f.write(payload)

        keyid = "c" * 64
        m_dict, m_bytes = build_manifest(
            artifact_path=art_path,
            package="core-agent",
            version="2.1.0",
            algorithm=ALG_ED25519,
            keyid=keyid,
        )
        assert m_dict["artifact"]["name"] == "release-archive.tar.gz"
        assert m_dict["artifact"]["size"] == len(payload)
        import hashlib
        assert m_dict["artifact"]["sha256"] == hashlib.sha256(payload).hexdigest().lower()
        assert parse_and_validate_manifest(m_bytes, enforce_canonical=True) == m_dict

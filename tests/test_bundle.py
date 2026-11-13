"""
Unit tests for bundle creation, parsing, and Base64 validation.
IF4020 Kriptografi Chapter 3 - Section 2.4 and Table 2.4.
"""

import base64
import json
import pytest

from norasign.bundle import (
    create_bundle,
    parse_and_validate_bundle,
    serialize_bundle,
    validate_rfc4648_base64,
)
from norasign.constants import MAX_BUNDLE_BYTES, SCHEMA_BUNDLE


def test_bundle_creation_and_parse():
    manifest_bytes = b'{"schema":"minisign-manifest/v1"}'
    sig_bytes = b"\xaa" * 64

    bundle_dict = create_bundle(manifest_bytes, sig_bytes)
    assert bundle_dict["schema"] == SCHEMA_BUNDLE
    assert "manifest_b64" in bundle_dict
    assert "signature_b64" in bundle_dict

    raw_json = serialize_bundle(bundle_dict)
    assert len(raw_json) <= MAX_BUNDLE_BYTES

    m_out, s_out, parsed_bundle = parse_and_validate_bundle(raw_json)
    assert m_out == manifest_bytes
    assert s_out == sig_bytes
    assert parsed_bundle["schema"] == SCHEMA_BUNDLE


def test_reject_whitespace_in_base64():
    # Base64 with whitespace inside
    valid_b64 = base64.b64encode(b"valid data").decode("ascii")
    with_space = valid_b64[:4] + " " + valid_b64[4:]
    with pytest.raises(ValueError, match="forbidden whitespace"):
        validate_rfc4648_base64(with_space)

    with_newline = valid_b64 + "\n"
    with pytest.raises(ValueError, match="forbidden whitespace"):
        validate_rfc4648_base64(with_newline)


def test_reject_invalid_padding_in_base64():
    # Base64 without proper padding
    b64_str = "YWJjZA" # 6 chars, invalid padding for 4 bytes 'abcd' (should be 'YWJjZA==')
    with pytest.raises(ValueError, match="Invalid Base64|not strictly canonical"):
        validate_rfc4648_base64(b64_str)


def test_reject_bundle_with_extra_fields():
    bad_bundle = {
        "schema": SCHEMA_BUNDLE,
        "manifest_b64": base64.b64encode(b"test").decode("ascii"),
        "signature_b64": base64.b64encode(b"sig").decode("ascii"),
        "private_key": "forbidden_secret_leaked",
    }
    raw = json.dumps(bad_bundle).encode("utf-8")
    with pytest.raises(ValueError, match="prohibited extra fields"):
        parse_and_validate_bundle(raw)


def test_reject_bundle_exceeding_64kib():
    oversized = b'{"schema":"minisign-bundle/v1"}' + (b" " * (MAX_BUNDLE_BYTES + 10))
    with pytest.raises(ValueError, match="exceeds maximum"):
        parse_and_validate_bundle(oversized)

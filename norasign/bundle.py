"""
Bundle construction, serialization, and RFC 4648 Base64 validation.
Implements Section 2.4 and Table 2.4 of IF4020 Tugas 3.
"""

import base64
import collections
import json
from typing import Any, Dict, Tuple

from norasign.constants import (
    BUNDLE_FIELD_ORDER,
    MAX_BUNDLE_BYTES,
    SCHEMA_BUNDLE,
)
from norasign.manifest import strict_json_pairs_hook


def validate_rfc4648_base64(b64_str: str) -> bytes:
    """
    Validates that a string is strictly encoded in standard Base64 (RFC 4648).
    - Prohibits whitespace (spaces, newlines, tabs) inside string.
    - Prohibits URL-safe alphabet characters (- or _).
    - Enforces proper padding =.
    - Verifies round-trip: b64encode(b64decode(s)) == s.
    Returns decoded bytes.
    """
    if not isinstance(b64_str, str):
        raise ValueError("Base64 value must be a string")

    # Check for any whitespace inside string
    if any(c.isspace() for c in b64_str):
        raise ValueError("Base64 string contains forbidden whitespace characters")

    # Decode and check strict validity
    try:
        raw_bytes = base64.b64decode(b64_str, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid Base64 encoding: {e}")

    # Canonical re-encoding check to ensure strict padding and standard alphabet
    re_encoded = base64.b64encode(raw_bytes).decode("ascii")
    if re_encoded != b64_str:
        raise ValueError("Base64 string is not strictly canonical RFC 4648")

    return raw_bytes


def create_bundle(manifest_bytes: bytes, signature_bytes: bytes) -> Dict[str, str]:
    """
    Create bundle dictionary from raw manifest bytes M and raw signature bytes sigma.
    """
    manifest_b64 = base64.b64encode(manifest_bytes).decode("ascii")
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    bundle = collections.OrderedDict()
    bundle["schema"] = SCHEMA_BUNDLE
    bundle["manifest_b64"] = manifest_b64
    bundle["signature_b64"] = signature_b64

    return bundle


def serialize_bundle(bundle: Dict[str, Any], indent: int = 2) -> bytes:
    """
    Serialize bundle to UTF-8 JSON bytes (without BOM).
    Maximum bundle size is 64 KiB (65,536 bytes).
    """
    text = json.dumps(bundle, indent=indent) + "\n"
    raw_bytes = text.encode("utf-8")

    if len(raw_bytes) > MAX_BUNDLE_BYTES:
        raise ValueError(
            f"Bundle size ({len(raw_bytes)} bytes) exceeds maximum {MAX_BUNDLE_BYTES} bytes"
        )

    return raw_bytes


def parse_and_validate_bundle(raw_bytes: bytes) -> Tuple[bytes, bytes, Dict[str, Any]]:
    """
    Strictly parses and validates bundle JSON bytes:
    - Checks length <= 64 KiB.
    - Checks no UTF-8 BOM.
    - Checks no duplicate fields.
    - Validates schema is 'minisign-bundle/v1'.
    - Validates no extra fields (only schema, manifest_b64, signature_b64).
    - Validates RFC 4648 Base64 for manifest_b64 and signature_b64.
    Returns (manifest_bytes, signature_bytes, bundle_dict).
    """
    if len(raw_bytes) > MAX_BUNDLE_BYTES:
        raise ValueError(
            f"Bundle size ({len(raw_bytes)} bytes) exceeds maximum {MAX_BUNDLE_BYTES} bytes"
        )

    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise ValueError("Bundle contains UTF-8 BOM (Byte Order Mark) which is prohibited")

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"Bundle is not valid UTF-8: {e}")

    try:
        bundle = json.loads(text, object_pairs_hook=strict_json_pairs_hook)
    except Exception as e:
        raise ValueError(f"Failed to parse bundle JSON: {e}")

    if not isinstance(bundle, dict):
        raise ValueError("Bundle JSON root must be an object")

    # Validate schema
    if bundle.get("schema") != SCHEMA_BUNDLE:
        raise ValueError(f"Invalid bundle schema: expected '{SCHEMA_BUNDLE}', got '{bundle.get('schema')}'")

    # Prohibit extra fields (note: order of fields in bundle is flexible per spec, but no extra fields allowed)
    allowed_fields = set(BUNDLE_FIELD_ORDER)
    actual_fields = set(bundle.keys())
    extra_fields = actual_fields - allowed_fields
    if extra_fields:
        raise ValueError(f"Bundle contains prohibited extra fields: {extra_fields}")
    missing_fields = allowed_fields - actual_fields
    if missing_fields:
        raise ValueError(f"Bundle is missing required fields: {missing_fields}")

    # Validate Base64 fields
    manifest_bytes = validate_rfc4648_base64(bundle["manifest_b64"])
    signature_bytes = validate_rfc4648_base64(bundle["signature_b64"])

    return manifest_bytes, signature_bytes, bundle

"""
Release Manifest parser, validator, and canonical serializer.
Implements Section 2.3 and Table 2.3 of IF4020 Tugas 3.
"""

import collections
import hashlib
import json
import os
from typing import Any, Dict, Tuple

from norasign.constants import (
    ALG_ECDSA_P256,
    ALG_ED25519,
    ALG_RSA_PSS,
    ARTIFACT_FIELD_ORDER,
    MANIFEST_FIELD_ORDER,
    MAX_ARTIFACT_SIZE,
    MAX_MANIFEST_BYTES,
    RE_ARTIFACT_NAME,
    RE_KEYID,
    RE_PACKAGE,
    RE_SHA256,
    RE_VERSION,
    SCHEMA_MANIFEST,
    SUPPORTED_ALGORITHMS,
)


def strict_json_pairs_hook(pairs):
    """
    JSON object pairs hook that detects and rejects duplicate field names.
    Raises ValueError immediately if a duplicate key is detected.
    """
    result = collections.OrderedDict()
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate field detected in JSON: '{key}'")
        result[key] = value
    return result


def serialize_manifest(manifest: Dict[str, Any]) -> bytes:
    """
    Serializes manifest into canonical JSON byte sequence M:
    - UTF-8 without BOM.
    - No whitespace outside strings (separators=(',', ':')).
    - No newline character at the end or inside outside strings.
    - Strict field order: schema, package, version, algorithm, keyid, artifact.
    - Artifact field order: name, size, sha256.
    - Maximum size: 16 KiB (16,384 bytes).
    """
    # Build strictly ordered manifest dictionary
    ordered_artifact = collections.OrderedDict()
    ordered_artifact["name"] = manifest["artifact"]["name"]
    ordered_artifact["size"] = manifest["artifact"]["size"]
    ordered_artifact["sha256"] = manifest["artifact"]["sha256"]

    ordered_manifest = collections.OrderedDict()
    ordered_manifest["schema"] = manifest["schema"]
    ordered_manifest["package"] = manifest["package"]
    ordered_manifest["version"] = manifest["version"]
    ordered_manifest["algorithm"] = manifest["algorithm"]
    ordered_manifest["keyid"] = manifest["keyid"]
    ordered_manifest["artifact"] = ordered_artifact

    # json.dumps without whitespace, ensure ASCII characters are written directly
    serialized_str = json.dumps(
        ordered_manifest,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    raw_bytes = serialized_str.encode("utf-8")

    if len(raw_bytes) > MAX_MANIFEST_BYTES:
        raise ValueError(
            f"Serialized manifest size ({len(raw_bytes)} bytes) exceeds maximum allowed {MAX_MANIFEST_BYTES} bytes"
        )

    return raw_bytes


def parse_and_validate_manifest(raw_bytes: bytes, enforce_canonical: bool = True) -> Dict[str, Any]:
    """
    Strictly parse and validate manifest bytes M:
    - Checks length <= 16 KiB.
    - Checks no UTF-8 BOM.
    - Checks no duplicate keys.
    - Checks required fields, absence of extra fields, no null values.
    - Checks field types, value ranges, and regex constraints.
    - If enforce_canonical is True, checks canonical serialization byte-for-byte.
    """
    if len(raw_bytes) > MAX_MANIFEST_BYTES:
        raise ValueError(
            f"Manifest size ({len(raw_bytes)} bytes) exceeds maximum {MAX_MANIFEST_BYTES} bytes"
        )

    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise ValueError("Manifest contains UTF-8 BOM (Byte Order Mark) which is prohibited")

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"Manifest is not valid UTF-8: {e}")

    # Detect duplicate fields during parsing
    try:
        manifest = json.loads(text, object_pairs_hook=strict_json_pairs_hook)
    except Exception as e:
        raise ValueError(f"Failed to parse manifest JSON: {e}")

    if not isinstance(manifest, dict):
        raise ValueError("Manifest JSON root must be an object")

    # Validate exact top-level fields
    top_keys = list(manifest.keys())
    if top_keys != MANIFEST_FIELD_ORDER:
        raise ValueError(
            f"Manifest fields must strictly be {MANIFEST_FIELD_ORDER}, got {top_keys}"
        )

    # Check for null values
    for k, v in manifest.items():
        if v is None:
            raise ValueError(f"Manifest field '{k}' has prohibited null value")

    # Validate schema
    if manifest["schema"] != SCHEMA_MANIFEST:
        raise ValueError(f"Invalid schema: expected '{SCHEMA_MANIFEST}', got '{manifest['schema']}'")

    # Validate package
    if not isinstance(manifest["package"], str) or not RE_PACKAGE.match(manifest["package"]):
        raise ValueError(f"Package name '{manifest['package']}' violates format pattern")

    # Validate version
    if not isinstance(manifest["version"], str) or not RE_VERSION.match(manifest["version"]):
        raise ValueError(f"Version '{manifest['version']}' violates format pattern")

    # Validate algorithm string
    if not isinstance(manifest["algorithm"], str):
        raise ValueError("Algorithm must be a string")

    # Validate keyid
    if not isinstance(manifest["keyid"], str) or not RE_KEYID.match(manifest["keyid"]):
        raise ValueError(f"Key ID '{manifest['keyid']}' is not a valid 64-char lowercase hex string")

    # Validate artifact object
    artifact = manifest["artifact"]
    if not isinstance(artifact, dict):
        raise ValueError("Field 'artifact' must be an object")

    art_keys = list(artifact.keys())
    if art_keys != ARTIFACT_FIELD_ORDER:
        raise ValueError(
            f"Artifact object fields must strictly be {ARTIFACT_FIELD_ORDER}, got {art_keys}"
        )

    for k, v in artifact.items():
        if v is None:
            raise ValueError(f"Artifact field '{k}' has prohibited null value")

    # Validate artifact.name
    if not isinstance(artifact["name"], str) or not RE_ARTIFACT_NAME.match(artifact["name"]):
        raise ValueError(f"Artifact name '{artifact['name']}' violates format pattern")

    # Validate artifact.size: must be integer, cannot be bool or float
    size = artifact["size"]
    if isinstance(size, bool) or not isinstance(size, int):
        raise ValueError(f"Artifact size must be an integer, got {type(size).__name__}")
    if size < 0 or size > MAX_ARTIFACT_SIZE:
        raise ValueError(f"Artifact size {size} is outside range [0, {MAX_ARTIFACT_SIZE}]")

    # Validate artifact.sha256
    if not isinstance(artifact["sha256"], str) or not RE_SHA256.match(artifact["sha256"]):
        raise ValueError(f"Artifact sha256 '{artifact['sha256']}' is not a valid 64-char lowercase hex string")

    # Canonical serialization verification (byte-for-byte)
    if enforce_canonical:
        reconstructed_bytes = serialize_manifest(manifest)
        if reconstructed_bytes != raw_bytes:
            raise ValueError("Manifest bytes do not match canonical serialization byte-for-byte")

    return manifest


def build_manifest(
    artifact_path: str,
    package: str,
    version: str,
    algorithm: str,
    keyid: str,
) -> Tuple[Dict[str, Any], bytes]:
    """
    Build canonical manifest from artifact file and release metadata:
    - Reads artifact file bytes without normalization.
    - Computes file SHA-256 and size.
    - Uses basename of artifact_path for artifact.name.
    - Returns (manifest_dict, canonical_bytes).
    """
    if not os.path.isfile(artifact_path):
        raise FileNotFoundError(f"Artifact file not found: {artifact_path}")

    # Read artifact without normalization
    with open(artifact_path, "rb") as f:
        artifact_bytes = f.read()

    artifact_size = len(artifact_bytes)
    artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest().lower()
    artifact_name = os.path.basename(artifact_path)

    if not RE_PACKAGE.match(package):
        raise ValueError(f"Invalid package name '{package}'")
    if not RE_VERSION.match(version):
        raise ValueError(f"Invalid version string '{version}'")
    if not RE_ARTIFACT_NAME.match(artifact_name):
        raise ValueError(f"Invalid artifact filename '{artifact_name}'")
    if not RE_KEYID.match(keyid):
        raise ValueError(f"Invalid keyid '{keyid}'")
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'")

    manifest = collections.OrderedDict()
    manifest["schema"] = SCHEMA_MANIFEST
    manifest["package"] = package
    manifest["version"] = version
    manifest["algorithm"] = algorithm
    manifest["keyid"] = keyid
    manifest["artifact"] = collections.OrderedDict([
        ("name", artifact_name),
        ("size", artifact_size),
        ("sha256", artifact_sha256),
    ])

    canonical_bytes = serialize_manifest(manifest)
    return manifest, canonical_bytes

"""
Release verification pipeline (Section 2.7, Table 2.8 - 2.10).
Checks run in a fixed order and stop at the first failure.
"""

import collections
import hashlib
import json
import os
import sys
from typing import Any, Dict, Optional

from norasign.bundle import parse_and_validate_bundle
from norasign.constants import (
    EXIT_SUCCESS,
    EXIT_USAGE_OR_IO_ERROR,
    EXIT_VERIFY_REJECTED,
    MAX_BUNDLE_BYTES,
    SIGNATURE_LENGTHS,
    STATUS_ARTIFACT_MISMATCH,
    STATUS_FORMAT_ERROR,
    STATUS_INPUT_ERROR,
    STATUS_INVALID_SIGNATURE,
    STATUS_KEY_NOT_TRUSTED,
    STATUS_METADATA_MISMATCH,
    STATUS_OK,
    STATUS_UNSUPPORTED_ALGORITHM,
    SUPPORTED_ALGORITHMS,
)
from norasign.crypto import verify_message_signature
from norasign.manifest import parse_and_validate_manifest
from norasign.trust import (
    KeyNotTrustedError,
    TrustStoreError,
    TrustStoreIOError,
    find_trusted_key,
    parse_trust_store,
    read_trust_store_bytes,
)

HASH_CHUNK = 1024 * 1024


def exit_code_for(status: str) -> int:
    if status == STATUS_OK:
        return EXIT_SUCCESS
    if status == STATUS_INPUT_ERROR:
        return EXIT_USAGE_OR_IO_ERROR
    return EXIT_VERIFY_REJECTED


def _result(status: str, message: str, manifest: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    m = manifest or {}
    res = collections.OrderedDict()
    res["valid"] = status == STATUS_OK
    res["status"] = status
    res["message"] = message
    res["algorithm"] = m.get("algorithm")
    res["keyid"] = m.get("keyid")
    res["package"] = m.get("package")
    res["version"] = m.get("version")
    return res


def _read_limited(path: str, limit: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(limit + 1)


def _hash_artifact(path: str):
    """Stream the artifact once; returns (size, sha256_hex). Content is never modified."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


def run_verification(
    file_path: Optional[str],
    bundle_path: Optional[str],
    trust_store_path: Optional[str],
    package: Optional[str],
    version: Optional[str],
) -> Dict[str, Any]:
    """Run the pipeline and return the Table 2.9 result without printing."""

    # 1. INPUT_ERROR
    for name, value in (
        ("--file", file_path),
        ("--bundle", bundle_path),
        ("--trust-store", trust_store_path),
        ("--package", package),
        ("--version", version),
    ):
        if not value:
            return _result(STATUS_INPUT_ERROR, f"Missing required option {name}.")

    if not os.path.isfile(file_path):
        return _result(STATUS_INPUT_ERROR, f"Artifact file not found or not a regular file: {file_path}")
    try:
        bundle_raw = _read_limited(bundle_path, MAX_BUNDLE_BYTES)
    except OSError as e:
        return _result(STATUS_INPUT_ERROR, f"Cannot read bundle '{bundle_path}': {e.strerror or e}")
    try:
        trust_raw = read_trust_store_bytes(trust_store_path)
    except TrustStoreIOError as e:
        return _result(STATUS_INPUT_ERROR, str(e))
    try:
        actual_size, actual_sha256 = _hash_artifact(file_path)
    except OSError as e:
        return _result(STATUS_INPUT_ERROR, f"Cannot read artifact '{file_path}': {e.strerror or e}")

    # 2. FORMAT_ERROR: bundle, manifest, trust store
    try:
        manifest_bytes, signature, _ = parse_and_validate_bundle(bundle_raw)
    except ValueError as e:
        return _result(STATUS_FORMAT_ERROR, f"Bundle format error: {e}")
    try:
        manifest = parse_and_validate_manifest(manifest_bytes, enforce_canonical=True)
    except (ValueError, KeyError, TypeError) as e:
        return _result(STATUS_FORMAT_ERROR, f"Manifest format error: {e}")
    try:
        entries = parse_trust_store(trust_raw)
    except TrustStoreError as e:
        return _result(STATUS_FORMAT_ERROR, f"Trust store format error: {e}", manifest)

    # 3. UNSUPPORTED_ALGORITHM
    algorithm = manifest["algorithm"]
    if algorithm not in SUPPORTED_ALGORITHMS:
        return _result(STATUS_UNSUPPORTED_ALGORITHM, f"Algorithm '{algorithm}' is not supported.", manifest)

    # 4. KEY_NOT_TRUSTED
    try:
        public_key = find_trusted_key(entries, manifest["keyid"], algorithm, package)
    except KeyNotTrustedError as e:
        return _result(STATUS_KEY_NOT_TRUSTED, f"Key not trusted: {e}.", manifest)

    # 5. INVALID_SIGNATURE over the exact manifest bytes from the bundle
    if len(signature) != SIGNATURE_LENGTHS[algorithm]:
        return _result(
            STATUS_INVALID_SIGNATURE,
            f"Signature length {len(signature)} bytes, expected {SIGNATURE_LENGTHS[algorithm]}.",
            manifest,
        )
    if not verify_message_signature(public_key, algorithm, manifest_bytes, signature):
        return _result(STATUS_INVALID_SIGNATURE, "Signature does not verify against the trusted key.", manifest)

    # 6. METADATA_MISMATCH
    if manifest["package"] != package:
        return _result(
            STATUS_METADATA_MISMATCH,
            f"Package mismatch: manifest '{manifest['package']}', expected '{package}'.",
            manifest,
        )
    if manifest["version"] != version:
        return _result(
            STATUS_METADATA_MISMATCH,
            f"Version mismatch: manifest '{manifest['version']}', expected '{version}'.",
            manifest,
        )
    basename = os.path.basename(file_path)
    if manifest["artifact"]["name"] != basename:
        return _result(
            STATUS_METADATA_MISMATCH,
            f"Artifact name mismatch: manifest '{manifest['artifact']['name']}', file '{basename}'.",
            manifest,
        )

    # 7. ARTIFACT_MISMATCH
    if manifest["artifact"]["size"] != actual_size:
        return _result(
            STATUS_ARTIFACT_MISMATCH,
            f"Artifact size mismatch: manifest {manifest['artifact']['size']}, file {actual_size}.",
            manifest,
        )
    if manifest["artifact"]["sha256"] != actual_sha256:
        return _result(STATUS_ARTIFACT_MISMATCH, "Artifact SHA-256 does not match the manifest.", manifest)

    # 8. OK
    return _result(STATUS_OK, "Tanda tangan dan artefak valid.", manifest)


def emit_result(result: Dict[str, Any], json_output: bool) -> None:
    if json_output:
        sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        if not result["valid"]:
            sys.stderr.write(f"norasign verify: {result['status']}: {result['message']}\n")
        return
    stream = sys.stdout if result["valid"] else sys.stderr
    stream.write(f"{result['status']}: {result['message']}\n")
    if result["keyid"] is not None:
        stream.write(
            f"  package={result['package']} version={result['version']} "
            f"algorithm={result['algorithm']} keyid={result['keyid']}\n"
        )


def verify_release(
    file_path: str,
    bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
    json_output: bool = False,
    emit: bool = True,
) -> Dict[str, Any]:
    try:
        result = run_verification(file_path, bundle_path, trust_store_path, package, version)
    except OSError as e:
        result = _result(STATUS_INPUT_ERROR, f"I/O error: {e}")
    if emit:
        emit_result(result, json_output)
    return result

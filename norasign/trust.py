"""
Trust store management (Section 2.5, Table 2.6).
"""

import base64
import binascii
import collections
import json
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization

from norasign.constants import (
    RE_KEYID,
    RE_PACKAGE,
    SCHEMA_TRUST,
    SUPPORTED_ALGORITHMS,
)
from norasign.crypto import load_public_key_pem
from norasign.manifest import strict_json_pairs_hook

MAX_TRUST_STORE_BYTES = 1024 * 1024
TRUST_FIELDS = ["schema", "keys"]
KEY_ENTRY_FIELDS = ["keyid", "algorithm", "public_key_pem", "packages"]

_PEM_PUBLIC_RE = re.compile(
    r"^\s*-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----\s*$"
)


class TrustStoreError(Exception):
    """Trust store content violates Table 2.6."""


class TrustStoreIOError(Exception):
    """Trust store cannot be read or written."""


class KeyNotTrustedError(Exception):
    """Key is absent, has a different profile, or lacks permission for the package."""


class TrustEntryNotFound(Exception):
    """No trust store entry with the requested keyid."""


def parse_public_key_strict(pem_text: str):
    """
    Parse an SPKI PEM public key and require that its DER equals the canonical
    re-export, so non-standard encodings (compressed EC points, Ed25519 with
    parameters, RSA-PSS OID) are rejected. Line endings and PEM wrapping are free.
    Returns (public_key, algorithm, keyid).
    """
    if not isinstance(pem_text, str):
        raise TrustStoreError("public_key_pem must be a string")
    match = _PEM_PUBLIC_RE.match(pem_text)
    if not match:
        raise TrustStoreError("public_key_pem is not a single PEM block labelled PUBLIC KEY")
    body = re.sub(r"\s+", "", match.group(1))
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as e:
        raise TrustStoreError(f"public_key_pem has invalid Base64 body: {e}")

    try:
        key, algorithm, keyid = load_public_key_pem(pem_text.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as e:
        raise TrustStoreError(f"invalid public key: {e}")

    canonical_der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if der != canonical_der:
        raise TrustStoreError("public key SPKI encoding is not the standard DER encoding for its profile")
    return key, algorithm, keyid


def _validate_entry(index: int, entry: Any) -> Dict[str, Any]:
    where = f"keys[{index}]"
    if not isinstance(entry, dict):
        raise TrustStoreError(f"{where} must be an object")
    fields = set(entry.keys())
    if fields != set(KEY_ENTRY_FIELDS):
        extra = sorted(fields - set(KEY_ENTRY_FIELDS))
        missing = sorted(set(KEY_ENTRY_FIELDS) - fields)
        raise TrustStoreError(f"{where} fields invalid (extra={extra}, missing={missing})")

    keyid = entry["keyid"]
    algorithm = entry["algorithm"]
    packages = entry["packages"]

    if not isinstance(keyid, str) or not RE_KEYID.match(keyid):
        raise TrustStoreError(f"{where}.keyid must be 64 lowercase hex characters")
    if not isinstance(algorithm, str):
        raise TrustStoreError(f"{where}.algorithm must be a string")
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise TrustStoreError(f"{where}.algorithm '{algorithm}' is not a supported profile")
    if not isinstance(packages, list) or not packages:
        raise TrustStoreError(f"{where}.packages must be a non-empty array")
    for pkg in packages:
        if not isinstance(pkg, str) or not RE_PACKAGE.match(pkg):
            raise TrustStoreError(f"{where}.packages contains invalid package name {pkg!r}")
    if len(set(packages)) != len(packages):
        raise TrustStoreError(f"{where}.packages contains duplicates")

    try:
        key, real_algorithm, real_keyid = parse_public_key_strict(entry["public_key_pem"])
    except TrustStoreError as e:
        raise TrustStoreError(f"{where}: {e}")
    if real_algorithm != algorithm:
        raise TrustStoreError(
            f"{where}.algorithm '{algorithm}' does not match key type '{real_algorithm}'"
        )
    if real_keyid != keyid:
        raise TrustStoreError(f"{where}.keyid does not match fingerprint of public_key_pem")

    return {
        "keyid": keyid,
        "algorithm": algorithm,
        "public_key_pem": entry["public_key_pem"],
        "packages": list(packages),
        "public_key": key,
    }


def parse_trust_store(raw: bytes) -> List[Dict[str, Any]]:
    """Strictly parse trust store bytes. Raises TrustStoreError on any format violation."""
    if len(raw) > MAX_TRUST_STORE_BYTES:
        raise TrustStoreError(f"trust store exceeds {MAX_TRUST_STORE_BYTES} bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise TrustStoreError("trust store contains UTF-8 BOM")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise TrustStoreError(f"trust store is not valid UTF-8: {e}")
    try:
        doc = json.loads(text, object_pairs_hook=strict_json_pairs_hook)
    except (ValueError, RecursionError) as e:
        raise TrustStoreError(f"trust store JSON invalid: {e}")

    if not isinstance(doc, dict):
        raise TrustStoreError("trust store root must be an object")
    if set(doc.keys()) != set(TRUST_FIELDS):
        raise TrustStoreError(f"trust store fields must be exactly {TRUST_FIELDS}, got {list(doc.keys())}")
    if doc["schema"] != SCHEMA_TRUST:
        raise TrustStoreError(f"trust store schema must be '{SCHEMA_TRUST}'")
    if not isinstance(doc["keys"], list):
        raise TrustStoreError("trust store 'keys' must be an array")

    entries = []
    seen = set()
    for i, raw_entry in enumerate(doc["keys"]):
        entry = _validate_entry(i, raw_entry)
        if entry["keyid"] in seen:
            raise TrustStoreError(f"duplicate keyid {entry['keyid']} in trust store")
        seen.add(entry["keyid"])
        entries.append(entry)
    return entries


def read_trust_store_bytes(store_path: str) -> bytes:
    try:
        with open(store_path, "rb") as f:
            return f.read(MAX_TRUST_STORE_BYTES + 1)
    except OSError as e:
        raise TrustStoreIOError(f"cannot read trust store '{store_path}': {e.strerror or e}")


def load_trust_store(store_path: str) -> List[Dict[str, Any]]:
    return parse_trust_store(read_trust_store_bytes(store_path))


def serialize_trust_store(entries: List[Dict[str, Any]]) -> bytes:
    doc = collections.OrderedDict()
    doc["schema"] = SCHEMA_TRUST
    doc["keys"] = [
        collections.OrderedDict(
            [
                ("keyid", e["keyid"]),
                ("algorithm", e["algorithm"]),
                ("public_key_pem", e["public_key_pem"]),
                ("packages", list(e["packages"])),
            ]
        )
        for e in entries
    ]
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def save_trust_store_atomic(store_path: str, entries: List[Dict[str, Any]]) -> None:
    """Write to a temp file in the same directory, fsync, then os.replace."""
    data = serialize_trust_store(entries)
    directory = os.path.dirname(os.path.abspath(store_path))
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".trust-", suffix=".tmp", dir=directory)
    except OSError as e:
        raise TrustStoreIOError(f"cannot prepare trust store write in '{directory}': {e.strerror or e}")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(store_path):
            try:
                os.chmod(tmp_path, os.stat(store_path).st_mode & 0o777)
            except OSError:
                pass
        else:
            os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, store_path)
    except OSError as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise TrustStoreIOError(f"cannot write trust store '{store_path}': {e.strerror or e}")

    try:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def trust_add(key_path: str, package: str, store_path: str, quiet: bool = False) -> Dict[str, Any]:
    """
    Authorize a public key for a package. Creates the store if it does not exist,
    appends the package to an existing entry, and is idempotent for an existing pair.
    """
    if not isinstance(package, str) or not RE_PACKAGE.match(package):
        raise TrustStoreError(f"invalid package name '{package}' (wildcards are not allowed)")

    try:
        with open(key_path, "rb") as f:
            pem_bytes = f.read(MAX_TRUST_STORE_BYTES)
    except OSError as e:
        raise TrustStoreIOError(f"cannot read public key '{key_path}': {e.strerror or e}")
    try:
        pem_text = pem_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise TrustStoreError("public key file is not ASCII PEM")
    if "PRIVATE KEY" in pem_text:
        raise TrustStoreError("refusing to add a private key; pass the .pub.pem file")
    key, algorithm, keyid = parse_public_key_strict(pem_text)
    canonical_pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    entries = load_trust_store(store_path) if os.path.exists(store_path) else []

    action = "added"
    target = next((e for e in entries if e["keyid"] == keyid), None)
    if target is None:
        entries.append(
            {
                "keyid": keyid,
                "algorithm": algorithm,
                "public_key_pem": canonical_pem,
                "packages": [package],
            }
        )
        target = entries[-1]
    elif package in target["packages"]:
        action = "unchanged"
    else:
        target["packages"].append(package)
        action = "updated"

    if action != "unchanged" or not os.path.exists(store_path):
        save_trust_store_atomic(store_path, entries)

    if not quiet:
        print(f"Trust store: {store_path} ({action})")
        print(f"  Fingerprint: {keyid}")
        print(f"  Algorithm:   {algorithm}")
        print(f"  Packages:    {', '.join(target['packages'])}")
    return {
        "action": action,
        "keyid": keyid,
        "algorithm": algorithm,
        "packages": list(target["packages"]),
    }


def trust_list(store_path: str, quiet: bool = False) -> List[Dict[str, Any]]:
    entries = load_trust_store(store_path)
    result = [
        {"keyid": e["keyid"], "algorithm": e["algorithm"], "packages": list(e["packages"])}
        for e in entries
    ]
    if not quiet:
        if not result:
            print(f"Trust store {store_path} is empty (no key is trusted).")
        for e in result:
            print(f"{e['keyid']}  {e['algorithm']}  {','.join(e['packages'])}")
    return result


def trust_remove(keyid: str, store_path: str, quiet: bool = False) -> Dict[str, Any]:
    entries = load_trust_store(store_path)
    remaining = [e for e in entries if e["keyid"] != keyid]
    if len(remaining) == len(entries):
        raise TrustEntryNotFound(f"keyid '{keyid}' not found in trust store '{store_path}'")
    removed = next(e for e in entries if e["keyid"] == keyid)
    save_trust_store_atomic(store_path, remaining)
    if not quiet:
        print(f"Removed key {keyid} ({removed['algorithm']}) from {store_path}")
    return {"keyid": keyid, "algorithm": removed["algorithm"], "packages": list(removed["packages"])}


def find_trusted_key(
    entries: List[Dict[str, Any]],
    keyid: str,
    algorithm: str,
    package: str,
) -> Any:
    """Return the public key object if trusted, otherwise raise KeyNotTrustedError."""
    entry = next((e for e in entries if e["keyid"] == keyid), None)
    if entry is None:
        raise KeyNotTrustedError(f"key {keyid} is not in the trust store")
    if entry["algorithm"] != algorithm:
        raise KeyNotTrustedError(
            f"key {keyid} is trusted for profile '{entry['algorithm']}', manifest uses '{algorithm}'"
        )
    if package not in entry["packages"]:
        raise KeyNotTrustedError(f"key {keyid} is not authorized for package '{package}'")
    return entry["public_key"]


def check_trust(store_path: str, keyid: str, algorithm: str, package: str) -> Optional[Any]:
    return find_trusted_key(load_trust_store(store_path), keyid, algorithm, package)


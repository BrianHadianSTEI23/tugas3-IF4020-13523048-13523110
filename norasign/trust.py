"""
Trust Store Management module for NoraSign.
IF4020 Kriptografi Chapter 3 - Section 2.5 and Table 2.6.

Assigned to: Andrew Isra Saputra DB (NIM 13523110).

Specification Checklist for Component 3:
- Schema: "minisign-trust/v1"
- Structure:
  {
    "schema": "minisign-trust/v1",
    "keys": [
      {
        "keyid": "<64 hex lowercase>",
        "algorithm": "<profil>",
        "public_key_pem": "<PEM string>",
        "packages": ["<pkg1>", "<pkg2>"]
      }
    ]
  }
- Atomic file write: write to temp file on same filesystem, flush & fsync, then os.replace.
- Idempotent `trust add`: if keyid and package already present, do nothing. If key exists but package is new, append package. If new key, add entry.
- `trust remove`: removes entry by keyid. If keyid not found, exit code 2.
- `trust list`: displays keyid, algorithm, and packages list.
- Reject wildcards (* or ?) in packages.
- Validate keyid == hex_lower(sha256(spki_der)).
"""

from typing import Any, Dict, List, Optional


def trust_add(key_path: str, package: str, store_path: str) -> None:
    """
    Add public key authorization for a package to trust store.
    Assigned to NIM 13523110.
    """
    raise NotImplementedError(
        "Component 3 (Trust Store Management) is assigned to Andrew Isra Saputra DB (NIM 13523110)."
    )


def trust_list(store_path: str) -> List[Dict[str, Any]]:
    """
    List trusted keys and allowed packages in trust store.
    Assigned to NIM 13523110.
    """
    raise NotImplementedError(
        "Component 3 (Trust Store Management) is assigned to Andrew Isra Saputra DB (NIM 13523110)."
    )


def trust_remove(keyid: str, store_path: str) -> None:
    """
    Remove public key from trust store by keyid.
    Assigned to NIM 13523110.
    """
    raise NotImplementedError(
        "Component 3 (Trust Store Management) is assigned to Andrew Isra Saputra DB (NIM 13523110)."
    )


def check_trust(
    store_path: str,
    keyid: str,
    algorithm: str,
    package: str,
) -> Optional[Any]:
    """
    Check if keyid is trusted for the specified algorithm and package.
    Returns the loaded public key object if trusted.
    Assigned to NIM 13523110.
    """
    raise NotImplementedError(
        "Component 3 (Trust Store Management) is assigned to Andrew Isra Saputra DB (NIM 13523110)."
    )

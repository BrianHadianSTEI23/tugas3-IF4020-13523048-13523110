# Internal API: Trust Store (`norasign.trust`)

Implements Section 2.5 and Table 2.6. The trust store is a JSON file kept separately from artifacts and bundles. It is never updated from bundle content.

## File Format (`minisign-trust/v1`)

| Field | Type | Rule |
| :--- | :--- | :--- |
| `schema` | string | Fixed `minisign-trust/v1`. |
| `keys` | array | Key entries. May be empty (an empty store trusts nothing). `keyid` must be unique. |
| `keys[].keyid` | string | `hex_lower(SHA-256(DER_SPKI))`, must equal the fingerprint of `public_key_pem`. |
| `keys[].algorithm` | string | One of `rsa-pss-sha256`, `ecdsa-p256-sha256`, `ed25519`; must match the key type and parameters. |
| `keys[].public_key_pem` | string | SPKI PEM text (not a path). DER must be the standard encoding: RSA 3072/e=65537 `rsaEncryption`, P-256 named curve with uncompressed point, Ed25519 per RFC 8410 without parameters. |
| `keys[].packages` | array of string | Non-empty, no duplicates, each matching `^[a-z0-9][a-z0-9._-]{0,63}$` (wildcards rejected). |

Extra fields, missing fields, duplicate JSON keys, BOM, and files larger than 1 MiB are rejected.

## Functions

| Function | Input | Output | Errors |
| :--- | :--- | :--- | :--- |
| `trust_add(key_path: str, package: str, store_path: str, quiet: bool = False)` | Public key PEM path, package name, store path | `dict` with `action` (`added`/`updated`/`unchanged`), `keyid`, `algorithm`, `packages` | `TrustStoreError`, `TrustStoreIOError` |
| `trust_list(store_path: str, quiet: bool = False)` | Store path | `list[dict]` of `keyid`, `algorithm`, `packages` | `TrustStoreError`, `TrustStoreIOError` |
| `trust_remove(keyid: str, store_path: str, quiet: bool = False)` | Fingerprint, store path | `dict` of removed entry | `TrustEntryNotFound` (CLI exit 2) |
| `load_trust_store(store_path: str)` | Store path | `list[dict]` validated entries incl. `public_key` object | `TrustStoreError`, `TrustStoreIOError` |
| `parse_trust_store(raw: bytes)` | Raw JSON bytes | Same as above | `TrustStoreError` |
| `parse_public_key_strict(pem_text: str)` | PEM text | `(public_key, algorithm, keyid)` | `TrustStoreError` |
| `find_trusted_key(entries, keyid, algorithm, package)` | Validated entries and manifest values | Public key object | `KeyNotTrustedError` |
| `save_trust_store_atomic(store_path, entries)` | Path, entries | None | `TrustStoreIOError` |

## Atomic Update

`save_trust_store_atomic` writes to a temporary file in the same directory, calls `fsync`, then `os.replace` onto the target and `fsync`s the directory. A failure at any step deletes the temporary file and leaves the previous store intact. A malformed existing store is never overwritten by `trust add`.

## Example

```python
from norasign.trust import trust_add, load_trust_store, find_trusted_key

trust_add("keys/publisher.pub.pem", "contoh-app", "ci/trust.json")
entries = load_trust_store("ci/trust.json")
pub = find_trusted_key(entries, keyid, "ed25519", "contoh-app")
```

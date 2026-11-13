# Internal API: Release Bundle (`norasign.bundle`)

The `norasign.bundle` module provides utilities for packaging canonical manifests and digital signatures into release bundles.

## Key Functions

### `create_bundle(manifest_bytes: bytes, signature_bytes: bytes) -> Dict[str, str]`
Creates a bundle dictionary containing:
- `schema`: `"minisign-bundle/v1"`
- `manifest_b64`: RFC 4648 standard Base64 string of raw manifest bytes.
- `signature_b64`: RFC 4648 standard Base64 string of raw signature bytes.

### `serialize_bundle(bundle: Dict[str, Any], indent: int = 2) -> bytes`
Serializes bundle into JSON bytes.
- Validates bundle size $\le 65536$ bytes (64 KiB).

### `parse_and_validate_bundle(raw_bytes: bytes) -> Tuple[bytes, bytes, Dict[str, Any]]`
Parses and validates bundle bytes:
- Checks size $\le 64$ KiB.
- Prohibits UTF-8 BOM.
- Detects duplicate JSON keys.
- Prohibits extra or unknown fields.
- Validates RFC 4648 Base64 strictly.
- Returns `(manifest_bytes, signature_bytes, bundle_dict)`.

### `validate_rfc4648_base64(b64_str: str) -> bytes`
Validates that a string conforms strictly to RFC 4648 Base64:
- Rejects whitespace (newlines, spaces, tabs).
- Rejects URL-safe characters (`-`, `_`).
- Verifies canonical padding (`=`).
- Performs round-trip comparison: `b64encode(b64decode(s)) == s`.

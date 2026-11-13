# Internal API: Release Manifest (`norasign.manifest`)

The `norasign.manifest` module handles canonical manifest creation, strict parsing, duplicate field detection, and canonical validation.

## Key Functions

### `build_manifest(artifact_path: str, package: str, version: str, algorithm: str, keyid: str) -> Tuple[Dict[str, Any], bytes]`
Constructs an in-memory dictionary and canonical UTF-8 byte string $M$ from an artifact file.
- Reads artifact file without normalization.
- Computes SHA-256 and byte length.
- Validates all fields against Table 2.3 regex patterns.
- Returns `(manifest_dict, canonical_bytes)`.

### `serialize_manifest(manifest: Dict[str, Any]) -> bytes`
Serializes a manifest dictionary into canonical JSON bytes.
- Enforces field sequence: `schema, package, version, algorithm, keyid, artifact`.
- Enforces artifact sequence: `name, size, sha256`.
- Strips whitespace (`separators=(',', ':')`).
- Checks maximum size $\le 16384$ bytes.

### `parse_and_validate_manifest(raw_bytes: bytes, enforce_canonical: bool = True) -> Dict[str, Any]`
Strictly parses and verifies a manifest:
- Detects duplicate keys during parsing via `strict_json_pairs_hook`.
- Validates types, ranges, non-null values, and regex patterns.
- If `enforce_canonical` is enabled, performs byte-for-byte comparison with reconstructed canonical serialization.

### `strict_json_pairs_hook(pairs)`
Hook for `json.loads` that detects duplicate field names at any object nesting level.
- Raises `ValueError` upon detecting duplicate keys.

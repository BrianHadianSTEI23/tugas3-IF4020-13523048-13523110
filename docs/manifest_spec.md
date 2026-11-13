# Release Manifest & Bundle Specifications

## Release Manifest (`minisign-manifest/v1`)

The release manifest is a canonical JSON document capturing the metadata and integrity digest of the software artifact.

### Schema Fields

| Field | Type | Regex / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `schema` | string | Constant: `"minisign-manifest/v1"` | Manifest schema identifier |
| `package` | string | `^[a-z0-9][a-z0-9._-]{0,63}$` | Lowercase package name |
| `version` | string | `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` | Release version |
| `algorithm` | string | One of supported profiles | Cryptographic algorithm name |
| `keyid` | string | `^[0-9a-f]{64}$` | 64-character lowercase hex public key fingerprint |
| `artifact` | object | Exact fields: `name`, `size`, `sha256` | Artifact integrity descriptor |
| `artifact.name` | string | `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` | Basename of artifact file (no paths) |
| `artifact.size` | integer | $[0, 9007199254740991]$ | File size in bytes (IEEE 754 safe int) |
| `artifact.sha256` | string | `^[0-9a-f]{64}$` | 64-character lowercase hex SHA-256 digest |

### Canonical Serialization Rules
To guarantee byte-for-byte reproducibility:
1. **No UTF-8 BOM**: Prohibited from starting with `\xef\xbb\xbf`.
2. **Strict Field Sequencing**:
   - Manifest root: `schema`, `package`, `version`, `algorithm`, `keyid`, `artifact`.
   - Artifact object: `name`, `size`, `sha256`.
3. **Zero Whitespace**: No spaces, tabs, or newlines outside JSON string literals (`separators=(',', ':')`).
4. **No Trailing Newline**: The byte string terminates directly at the closing `}`.
5. **No Floats or Booleans for Size**: Boolean values like `true` or `false` are strictly rejected.
6. **Maximum Size**: Must not exceed 16 KiB (16,384 bytes).

---

## Release Bundle (`minisign-bundle/v1`)

The release bundle encapsulates the canonical manifest bytes and digital signature in a portable Base64-encoded JSON structure.

```json
{
  "schema": "minisign-bundle/v1",
  "manifest_b64": "<base64 encoded canonical manifest bytes>",
  "signature_b64": "<base64 encoded raw signature bytes>"
}
```

### Constraints
- Encoded using standard RFC 4648 Base64 with `=` padding.
- Prohibits whitespace (newlines, spaces) inside Base64 strings.
- Maximum bundle size: 64 KiB (65,536 bytes).
- Must not contain private keys or extra fields.

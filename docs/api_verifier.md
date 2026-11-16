# Internal API: Verifier (`norasign.verifier`)

Implements Section 2.7, Table 2.8, Table 2.9, and Table 2.10. Checks run in order and stop at the first failure without trying another key, profile, or trust store.

## Check Order

| No | Status on failure | Check |
| :--- | :--- | :--- |
| 1 | `INPUT_ERROR` | All options present; artifact, bundle, and trust store readable. Artifact size and SHA-256 are computed here by streaming (read only). |
| 2 | `FORMAT_ERROR` | Bundle (size, BOM, duplicate keys, fields, RFC 4648 Base64), manifest (size, strict types, canonical bytes), trust store (Table 2.6, key parameters, fingerprint). |
| 3 | `UNSUPPORTED_ALGORITHM` | `algorithm` is one of the three profiles. |
| 4 | `KEY_NOT_TRUSTED` | `keyid` exists in the store, entry profile equals manifest profile, and the expected `--package` is authorized. |
| 5 | `INVALID_SIGNATURE` | Signature length per profile and signature validity over the exact manifest bytes from the bundle. |
| 6 | `METADATA_MISMATCH` | Manifest `package`, `version`, and `artifact.name` equal `--package`, `--version`, and the artifact basename. |
| 7 | `ARTIFACT_MISMATCH` | Artifact size and SHA-256 equal manifest values. |
| 8 | `OK` | All checks pass. |

## Result (`--json`)

| Field | Type | Rule |
| :--- | :--- | :--- |
| `valid` | boolean | `true` only for `OK`. |
| `status` | string | Status from the table above. |
| `message` | string | Short explanation. |
| `algorithm` | string/null | From the manifest, `null` if the manifest could not be read. |
| `keyid` | string/null | Same rule. |
| `package` | string/null | Same rule. |
| `version` | string/null | Same rule. |

The JSON object is written to stdout followed by one newline. Diagnostics go to stderr.

## Functions

| Function | Description |
| :--- | :--- |
| `run_verification(file_path, bundle_path, trust_store_path, package, version) -> dict` | Runs the pipeline and returns the result without printing. |
| `verify_release(file_path, bundle_path, trust_store_path, package, version, json_output=False, emit=True) -> dict` | Runs the pipeline and prints the result (JSON or text). |
| `exit_code_for(status: str) -> int` | `0` for `OK`, `2` for `INPUT_ERROR`, `1` otherwise. |

## Example

```python
from norasign.verifier import run_verification, exit_code_for

res = run_verification("dist/app.zip", "out/release.json", "ci/trust.json", "contoh-app", "1.0.0")
if res["valid"]:
    print("deploy")
raise SystemExit(exit_code_for(res["status"]))
```

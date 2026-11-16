# Signed SBOM (Bonus 3)

NoraSign produces a CycloneDX 1.5 JSON SBOM, signs it as a separate artifact with the standard `minisign-bundle/v1` format, and verifies both bundles plus the SHA-256 binding between the SBOM and the release artifact.

## SBOM Data Format

| Field | Type | Rule |
| :--- | :--- | :--- |
| `bomFormat` | string | Fixed `CycloneDX`. |
| `specVersion` | string | Fixed `1.5`. |
| `serialNumber` | string | `urn:uuid:<uuid4>`. |
| `version` | integer | `1`. |
| `metadata.timestamp` | string | UTC ISO-8601. |
| `metadata.tools.components[]` | array | Generator (`norasign`). |
| `metadata.component.name` | string | Release package name (same pattern as manifest `package`). |
| `metadata.component.version` | string | Release version (same pattern as manifest `version`). |
| `metadata.component.hashes` | array | Exactly one entry with `alg` = `SHA-256` and lowercase hex `content`: the SHA-256 of the release artifact. |
| `metadata.component.properties` | array | Exactly one `norasign:artifact:name` and one `norasign:artifact:size` (decimal string). |
| `components[]` | array | Declared libraries (`--component name@version`) and, for zip/tar artifacts, archive members with their SHA-256. |

Duplicate JSON keys, BOM, and files over 4 MiB are rejected.

## Commands

| Command | Parameters | Output |
| :--- | :--- | :--- |
| `sbom generate` | `--artifact <path>` `--package <name>` `--version <ver>` `[--component NAME@VERSION]...` `[--no-scan]` `--out <sbom.json>` | SBOM file. Exit `0`, or `2` on input error. |
| `sbom sign` | `--sbom <sbom.json>` `--key <private.pem>` `--out <sbom.bundle.json>` | Bundle for the SBOM file. Package and version are read from the SBOM. Exit `0` or `2`. |
| `sbom verify` | `--artifact <path>` `--artifact-bundle <bundle.json>` `--sbom <sbom.json>` `--sbom-bundle <sbom.bundle.json>` `--trust-store <trust.json>` `--package <name>` `--version <ver>` `[--json]` | Verification result. Exit `0` (`OK`), `1` (rejected), `2` (`INPUT_ERROR`). |

SBOM signature verification alone can also be done with the standard `norasign verify --file sbom.json --bundle sbom.bundle.json ...`.

## Verification Steps

1. Verify the release bundle against the release artifact (full Table 2.8 pipeline).
2. Verify the SBOM bundle against the SBOM file (same pipeline, same trust store, same package and version).
3. Parse the SBOM strictly and check that its package, version, SHA-256, artifact name, and size equal the verified release artifact.

## `sbom verify --json` Output

| Field | Type | Rule |
| :--- | :--- | :--- |
| `valid` | boolean | `true` only if all three steps pass. |
| `status` | string | `OK`, a Table 2.8 status from the failing stage, or `SBOM_BINDING_MISMATCH`. |
| `stage` | string | `release`, `sbom`, or `binding`. |
| `message` | string | Short explanation. |
| `release` | object/null | Table 2.9 result of step 1. |
| `sbom` | object/null | Table 2.9 result of step 2. |
| `binding` | object/null | `sbom_artifact_sha256`, `release_artifact_sha256`, `sbom_artifact_name`, `release_artifact_name`, `components`. |

## Example

```bash
norasign sign --file dist/app.zip --package contoh-app --version 1.0.0 --key keys/pub.key.pem --out out/release.json
norasign sbom generate --artifact dist/app.zip --package contoh-app --version 1.0.0 \
  --component cryptography@46.0.0 --out out/app.sbom.json
norasign sbom sign --sbom out/app.sbom.json --key keys/pub.key.pem --out out/app.sbom.bundle.json
norasign sbom verify --artifact dist/app.zip --artifact-bundle out/release.json \
  --sbom out/app.sbom.json --sbom-bundle out/app.sbom.bundle.json \
  --trust-store ci/trust.json --package contoh-app --version 1.0.0 --json
```

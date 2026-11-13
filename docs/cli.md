# CLI Command Reference

NoraSign provides a command-line interface conforming strictly to Table 2.7 of the IF4020 specification.

## Global Options

- `--help`, `-h`: Show usage instructions.
- `--version`, `-v`: Display application version.

```bash
norasign --version
norasign --help
```

---

## 1. Key Generation (`keygen`)

Generates a cryptographic keypair matching the specified profile.

```bash
norasign keygen --algorithm <profile> --out <prefix> [--force]
```

### Parameters
| Option | Required | Description |
| :--- | :---: | :--- |
| `--algorithm` | Yes | Target algorithm profile: `rsa-pss-sha256`, `ecdsa-p256-sha256`, or `ed25519`. |
| `--out` | Yes | Output prefix path. Produces `<prefix>.key.pem` and `<prefix>.pub.pem`. |
| `--force`, `-f` | No | Allow overwriting existing private key file. |

### Output
- `<prefix>.key.pem`: PKCS#8 unencrypted PEM format (`PRIVATE KEY`), file permissions `0600`.
- `<prefix>.pub.pem`: SubjectPublicKeyInfo (SPKI) PEM format (`PUBLIC KEY`).
- Prints the 64-character lowercase hex public key fingerprint (keyid) to stdout.

---

## 2. Sign Release Artifact (`sign`)

Generates a release manifest and creates a digital signature bundle.

```bash
norasign sign --file <path> --package <name> --version <version> --key <private.pem> --out <bundle.json>
```

### Parameters
| Option | Required | Description |
| :--- | :---: | :--- |
| `--file` | Yes | Path to the release artifact (binary, archive, or document). |
| `--package` | Yes | Package identifier matching `^[a-z0-9][a-z0-9._-]{0,63}$`. |
| `--version` | Yes | Release version string matching `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`. |
| `--key` | Yes | Path to the signer's private key in PKCS#8 PEM format. |
| `--out` | Yes | Output file path for the generated bundle JSON. |

### Exit Codes
- `0`: Signing succeeded and bundle was written.
- `2`: Input or I/O error (unreadable file, invalid private key, missing parameters).

---

## 3. Verify Release (`verify`)

Verifies an artifact file against a signed bundle and trusted public keys.

```bash
norasign verify --file <path> --bundle <bundle.json> --trust-store <trust.json> --package <name> --version <version> [--json]
```

### Parameters
| Option | Required | Description |
| :--- | :---: | :--- |
| `--file` | Yes | Path to the candidate artifact file. |
| `--bundle` | Yes | Path to the signature bundle JSON. |
| `--trust-store` | Yes | Path to the trust store JSON containing authorized keys. |
| `--package` | Yes | Expected package name. |
| `--version` | Yes | Expected release version. |
| `--json` | No | Emit machine-readable single-line JSON result to stdout. |

### Exit Codes
- `0`: Verification succeeded (`OK`).
- `1`: Verification rejected (`FORMAT_ERROR`, `UNSUPPORTED_ALGORITHM`, `KEY_NOT_TRUSTED`, `INVALID_SIGNATURE`, `METADATA_MISMATCH`, `ARTIFACT_MISMATCH`).
- `2`: Input, environment, or I/O error (`INPUT_ERROR`).

---

## 4. Trust Store Management (`trust`)

### Add Key Authorization
```bash
norasign trust add --key <public.pem> --package <name> --store <trust.json>
```

### List Trusted Keys
```bash
norasign trust list --store <trust.json>
```

### Remove Key Authorization
```bash
norasign trust remove --keyid <fingerprint> --store <trust.json>
```

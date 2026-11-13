# NoraSign Documentation

**NoraSign** is a production-grade digital signature and software release verification utility designed for **IF4020 Kriptografi Semester 1 Tahun 2026/2027** at Institut Teknologi Bandung.

Modeled after the principles of [Sigstore Cosign blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/), NoraSign enables software release pipelines to bind build artifacts to canonical cryptographic manifests, sign them across multiple asymmetric algorithms, and verify provenance in offline or air-gapped CI/CD environments.

## Authors
- **Brian A. Hadian** (NIM 13523048)
- **Andrew Isra Saputra DB** (NIM 13523110)

## High-Level Workflow

```mermaid
flowchart LR
    subgraph Build ["Build Pipeline"]
        Art["Release Artifact<br/>(ZIP / TAR / BIN)"]
        Hash["Compute SHA-256"]
        Art --> Hash
        Hash --> Manifest["Generate Canonical Manifest<br/>(minisign-manifest/v1)"]
        PrivKey["Private Key (PKCS#8 PEM)"] --> Sign["Sign Manifest M"]
        Manifest --> Sign
        Sign --> Bundle["Generate Bundle JSON<br/>(minisign-bundle/v1)"]
    end

    subgraph Verify ["Verification Gate"]
        Bundle --> Verifier["8-Step Verification Pipeline"]
        Trust["Trust Store JSON"] --> Verifier
        Verifier --> Result{"Status"}
        Result -->|OK (Exit 0)| Deploy["Deploy Release"]
        Result -->|Reject (Exit 1/2)| Halt["Halt Pipeline"]
    end
```

## Key Capabilities

1. **Multi-Algorithm Asymmetric Cryptography**:
   - `rsa-pss-sha256`: RSA 3072-bit, RSASSA-PSS, MGF1-SHA-256, 32-byte salt, 384-byte signature.
   - `ecdsa-p256-sha256`: NIST P-256 (secp256r1), SHA-256, raw 64-byte `r || s` big-endian encoding.
   - `ed25519`: PureEdDSA (RFC 8032), direct manifest signing, 64-byte signature.

2. **Tamper-Proof Canonical Manifest**:
   - UTF-8 without BOM, whitespace-free serialization.
   - Strict field sequencing and recursive duplicate field rejection.
   - Exact size and schema bounds.

3. **Secure Base64 Bundling**:
   - RFC 4648 compliance with strict padding validation and whitespace prohibition.
   - Segregated private key boundary (private keys never serialized into bundles).

4. **Containerized CI/CD Integration**:
   - Zero runtime network dependency (`--network none`).
   - Supports arbitrary runner UID/GID via `--user`.
   - Native integration with GitHub Actions and GitHub Container Registry (`ghcr.io`).

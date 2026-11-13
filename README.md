# NoraSign — Cryptographic Software Release Signing & Verification CLI

> **IF4020 Kriptografi — Semester 1 Tahun 2026/2027**  
> Program Studi Teknik Informatika, Sekolah Teknik Elektro dan Informatika, Institut Teknologi Bandung

---

## Authors & Team Members
- **Brian A. Hadian** (13523048)
- **Andrew Isra Saputra DB** (13523110)

---

## 1. Description & Lore

**NoraSign** is a production-grade digital signature and software release verification kakas designed to protect software distribution channels against unauthorized binary tampering and supply chain compromise.

Inspired by the story of **Nora and ROBO** (from Cytus II as highlighted in the assignment briefing), NoraSign ensures that software updates received from maintenance relays or distribution mirrors are cryptographically bound to an authorized publisher before installation. It adapts the blob signing architecture of [Sigstore Cosign](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/) into an air-gapped, container-native tool with canonical manifest serialization and strict 8-step verification.

---

## 2. Technology Stack & Dependencies

- **Language**: Python 3.10+
- **Cryptographic Engine**: [`cryptography>=41.0.0`](https://cryptography.io/en/latest/) (OpenSSL 3-backed primitives)
- **Container Runtime**: Docker (OCI compliant `linux/amd64`)
- **CI/CD Platform**: GitHub Actions & GitHub Container Registry (`ghcr.io`)
- **Documentation**: MkDocs Material (`mkdocs-material`)
- **Testing**: `pytest`, `pytest-cov`, and `openssl` CLI

---

## 3. Cryptographic Profiles & Library Mapping

NoraSign supports three asymmetric digital signature profiles conforming to Table 2.1:

| Profile | Key Parameters | Signing API (`cryptography`) | Verification API (`cryptography`) | Signature Format |
| :--- | :--- | :--- | :--- | :--- |
| `rsa-pss-sha256` | RSA 3072-bit, $e = 65537$ | `key.sign(M, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())` | `pub.verify(sig, M, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())` | 384 bytes raw |
| `ecdsa-p256-sha256` | NIST P-256 (secp256r1) | `key.sign(M, ec.ECDSA(hashes.SHA256()))` $\rightarrow$ decode ASN.1 DER to $(r, s)$ | `encode_dss_signature(r, s)` $\rightarrow$ `pub.verify(der, M, ec.ECDSA(hashes.SHA256()))` | 64 bytes (`r \|\| s` 32B each) |
| `ed25519` | Curve25519 (RFC 8032) | `key.sign(M)` (PureEdDSA, no external pre-hash) | `pub.verify(sig, M)` | 64 bytes raw wire format |

### Key Fingerprint (`keyid`)
Public key fingerprint is computed deterministically as:
$$\text{keyid} = \text{hex\_lower}(\text{SHA-256}(\text{DER\_SPKI}))$$
where `DER_SPKI` is the raw byte sequence of the SubjectPublicKeyInfo in standard DER format.

---

## 4. Container Distribution & CI/CD Usage

The container image is published to GitHub Container Registry (GHCR) for the `linux/amd64` architecture.

### Pulling Image by Digest
To satisfy supply-chain security standards and Table 2.13, CI/CD workflows pin the container image using its immutable **SHA-256 digest**:

```bash
docker pull ghcr.io/brianhadianstei23/norasign:1.0.0
# Or by digest:
# docker pull ghcr.io/brianhadianstei23/norasign@sha256:<digest>
```

### Execution Contract on Runner
The image runs with **zero runtime network access** (`--network none`) and supports non-root execution matching the runner user (`--user "$(id -u):$(id -g)"`):

```bash
# 1. Sign Artifact in CI Runner
docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" \
  -v "$PWD/out:/output" \
  -v "$SIGNING_KEY_FILE:/run/signing.key.pem:ro" \
  ghcr.io/brianhadianstei23/norasign:1.0.0 sign \
  --file /input/my-app.tar.gz \
  --package my-app \
  --version 1.0.0 \
  --key /run/signing.key.pem \
  --out /output/release.bundle.json

# 2. Verify Release in CI Runner (without private key)
docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" \
  -v "$PWD/out:/output:ro" \
  -v "$PWD/ci/trust.json:/trust.json:ro" \
  ghcr.io/brianhadianstei23/norasign:1.0.0 verify \
  --file /input/my-app.tar.gz \
  --bundle /output/release.bundle.json \
  --trust-store /trust.json \
  --package my-app \
  --version 1.0.0 \
  --json > out/verification.json
```

---

## 5. Local Execution Guide (Outside Container)

### Installation
```bash
# Clone the repository
git clone git@github.com:BrianHadianSTEI23/tugas3-IF4020-13523048-13523110.git
cd tugas3-IF4020-13523048-13523110

# Install dependencies and editable CLI
pip install -r requirements.txt
pip install -e .
```

### Subcommand Examples

#### A. Key Generation
```bash
# Generate Ed25519 keypair
norasign keygen --algorithm ed25519 --out keys/publisher

# Generate RSA-PSS 3072 keypair
norasign keygen --algorithm rsa-pss-sha256 --out keys/rsa_publisher

# Generate ECDSA P-256 keypair
norasign keygen --algorithm ecdsa-p256-sha256 --out keys/ec_publisher
```

#### B. Trust Store Management
```bash
# Add public key authorization for package 'contoh-app'
norasign trust add --key keys/publisher.pub.pem --package contoh-app --store ci/trust.json

# List authorized keys
norasign trust list --store ci/trust.json

# Remove key
norasign trust remove --keyid <fingerprint> --store ci/trust.json
```

#### C. Sign Release Artifact
```bash
norasign sign \
  --file dist/contoh-app.zip \
  --package contoh-app \
  --version 1.0.0 \
  --key keys/publisher.key.pem \
  --out out/release.bundle.json
```

#### D. Verify Release
```bash
norasign verify \
  --file dist/contoh-app.zip \
  --bundle out/release.bundle.json \
  --trust-store ci/trust.json \
  --package contoh-app \
  --version 1.0.0 \
  --json
```

---

## 6. Testing & Benchmarking

### Running Automated Test Suite
```bash
pytest -v tests/
```

### Running OpenSSL Interoperability Tests
```bash
pytest -v tests/test_interop.py
```

### Running Performance Benchmarks (Table 2.12)
```bash
python scripts/benchmark.py --warmup 5 --runs 30 --out benchmark_results.md
```

### Running Local CI Container Scenarios (C01 - C05)
```bash
bash scripts/run_ci_scenarios.sh norasign:local
```

---

## 7. Division of Work

- **Brian A. Hadian (13523048)**:
  - System architecture and specification alignment.
  - Component 1: Cryptographic Engine (RSA-PSS, ECDSA P-256, Ed25519, Keygen, Fingerprinting).
  - Component 2: Release Manifest (Strict JSON duplicate detection, canonical serialization byte-for-byte) and Bundle engine.
  - Component 6: CLI parsing and packaging, Dockerfile (`linux/amd64`), container execution contracts.
  - Performance benchmarking suite (`scripts/benchmark.py`) and OpenSSL interoperability test suite (`tests/test_interop.py`).
  - GitHub Actions CI/CD workflows (`.github/workflows/ci.yml`, `docs.yml`).
  - Bonus 2: API Documentation setup via MkDocs and GitHub Pages.
  - Report preparation (Theoretical background, design diagrams, security mitigations, benchmark results).

- **Andrew Isra Saputra DB (13523110)**:
  - Component 3: Trust Store Management (`norasign/trust.py`) with atomic file updates.
  - Component 4: 8-Step Verification Pipeline (`norasign/verifier.py`) adhering to Table 2.8 and Algorithm 2.
  - Component 5: Bonus 3 Signed SBOM implementation (`norasign/sbom.py`).
  - Test scenarios U01 - U14 execution and failure analysis.
  - Bonus 1: Video Demo on-camera recording and presentation.

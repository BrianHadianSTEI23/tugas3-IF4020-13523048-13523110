# Cryptographic Profiles Specification

NoraSign supports three asymmetric digital signature algorithm profiles conforming to Table 2.1 of the IF4020 specification.

## Profile Summary

| Profile | Key Parameters | Hash & Mode | Salt / Nonce | Signature Size |
| :--- | :--- | :--- | :--- | :---: |
| `rsa-pss-sha256` | RSA 3072-bit, $e = 65537$ | RSASSA-PSS with SHA-256 and MGF1(SHA-256) | Salt: 32 bytes | 384 bytes |
| `ecdsa-p256-sha256` | NIST P-256 / secp256r1 | ECDSA with SHA-256 | CSPRNG or RFC 6979 | 64 bytes (`r \|\| s`) |
| `ed25519` | Curve25519 | PureEdDSA (RFC 8032) | Standard Ed25519 | 64 bytes |

---

## 1. RSA-PSS (`rsa-pss-sha256`)

- **Standard**: RFC 8017 (PKCS #1 v2.2).
- **Public Exponent**: 65537.
- **Modulus Size**: 3072 bits (128-bit cryptographic security level).
- **Padding**: Probabilistic Signature Scheme (PSS) using Mask Generation Function 1 (MGF1) based on SHA-256.
- **Salt Length**: Exactly 32 bytes (equal to SHA-256 output length).
- **API Mapping**:
  ```python
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import padding

  # Signing
  signature = private_key.sign(
      manifest_bytes,
      padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
      hashes.SHA256(),
  )

  # Verification
  public_key.verify(
      signature,
      manifest_bytes,
      padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
      hashes.SHA256(),
  )
  ```

---

## 2. ECDSA (`ecdsa-p256-sha256`)

- **Standard**: FIPS 186-5, ANSI X9.62.
- **Curve**: NIST P-256 (secp256r1 / prime256v1).
- **Hash**: SHA-256 applied once over manifest bytes $M$.
- **Wire Format**: IEEE P1363 raw concatenation `r || s`:
  - $r$: 32 bytes big-endian.
  - $s$: 32 bytes big-endian.
  - Total length: exactly 64 bytes.
- **ASN.1 DER Conversion**:
  When communicating with standard cryptographic libraries (which emit or consume ASN.1 DER sequences), NoraSign extracts the raw 32-byte big-endian integers $(r, s)$ for bundle storage, and reconstructs the DER sequence upon verification.

---

## 3. Ed25519 (`ed25519`)

- **Standard**: RFC 8032.
- **Mode**: PureEdDSA (Ed25519). The pre-hashed variant (Ed25519ph) is strictly prohibited.
- **Input**: The raw canonical manifest byte string $M$ is passed directly to the signing function without external hashing.
- **Signature Length**: 64 bytes standard Ed25519 wire format.
- **API Mapping**:
  ```python
  # Direct message signing
  signature = private_key.sign(manifest_bytes)

  # Direct message verification
  public_key.verify(signature, manifest_bytes)
  ```

---

## Public Key Fingerprinting (`keyid`)

To ensure deterministic, cross-platform identification of public keys regardless of PEM line-wrapping or line endings (`\r\n` vs `\n`), the `keyid` is computed directly over the canonical SubjectPublicKeyInfo (SPKI) DER bytes:

$$\text{keyid} = \text{hex\_lower}(\text{SHA-256}(\text{DER\_SPKI}))$$

This produces a unique 64-character lowercase hexadecimal string matching `^[0-9a-f]{64}$`.

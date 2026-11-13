# Internal API: Cryptographic Engine (`norasign.crypto`)

The `norasign.crypto` package provides cryptographic operations conforming to the assignment specification.

## Module Structure

```
norasign.crypto/
├── __init__.py        # High-level dispatcher (sign_message, verify_message_signature)
├── keys.py            # Keypair generation, PEM/DER encoding, fingerprint calculation
├── rsa_pss.py         # RSASSA-PSS implementation (3072-bit, 32-byte salt)
├── ecdsa_p256.py      # ECDSA P-256 implementation (raw r || s conversion)
└── ed25519.py         # Ed25519 implementation (RFC 8032 PureEdDSA)
```

---

## `norasign.crypto.keys`

### `generate_keypair(algorithm: str)`
Generates an asymmetric keypair conforming to the algorithm profile.
- **Parameters**: `algorithm` (`str`): one of `rsa-pss-sha256`, `ecdsa-p256-sha256`, `ed25519`.
- **Returns**: `Tuple[PrivateKey, PublicKey]`.

### `calculate_keyid(public_key)`
Calculates the 64-character lowercase hexadecimal fingerprint of a public key:
$$\text{keyid} = \text{hex\_lower}(\text{SHA-256}(\text{DER\_SPKI}))$$
- **Parameters**: `public_key`: RSAPublicKey, EllipticCurvePublicKey, or Ed25519PublicKey.
- **Returns**: `str`: 64 hex characters.

### `save_keypair_files(algorithm: str, out_prefix: str, overwrite: bool = False)`
Generates a keypair and saves `<out_prefix>.key.pem` (mode `0600`) and `<out_prefix>.pub.pem`.
- **Returns**: `Tuple[str, str, str]`: `(private_key_path, public_key_path, keyid)`.

---

## `norasign.crypto.sign_message`

```python
sign_message(private_key, algorithm: str, message: bytes) -> bytes
```
Signs arbitrary raw message bytes using the designated profile.
- Returns raw signature bytes:
  - `384` bytes for `rsa-pss-sha256`.
  - `64` bytes (`r || s`) for `ecdsa-p256-sha256`.
  - `64` bytes for `ed25519`.

---

## `norasign.crypto.verify_message_signature`

```python
verify_message_signature(public_key, algorithm: str, message: bytes, signature: bytes) -> bool
```
Verifies raw signature bytes over message bytes.
- Returns `True` if signature is valid.
- Returns `False` on signature mismatch, incorrect signature length, or out-of-domain parameters.

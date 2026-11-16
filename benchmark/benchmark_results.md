# NoraSign Performance Benchmark Report

- Date: 2026-11-16 12:42:15
- Warmup repetitions: 5
- Measured repetitions: 30
- Percentile metric: P95 calculated via nearest-rank `ceil(0.95 * n)`

## 1. Key Generation Duration

| Algorithm | Median (ms) | P95 (ms) |
| :--- | :---: | :---: |
| `rsa-pss-sha256` | 155.205 | 242.559 |
| `ecdsa-p256-sha256` | 0.014 | 0.082 |
| `ed25519` | 0.032 | 0.250 |

## 2. Artifact Hashing (SHA-256)

| Artifact Size | Median (ms) | P95 (ms) |
| :--- | :---: | :---: |
| 1 KB | 0.001 | 0.001 |
| 10 MB | 6.335 | 6.952 |
| 50 MB | 33.360 | 36.938 |

## 3. Cryptographic Operations (Sign & Verify)

| Algorithm | Sign Median (ms) | Sign P95 (ms) | Verify Median (ms) | Verify P95 (ms) |
| :--- | :---: | :---: | :---: | :---: |
| `rsa-pss-sha256` | 0.835 | 0.930 | 0.052 | 0.067 |
| `ecdsa-p256-sha256` | 0.029 | 0.045 | 0.074 | 0.095 |
| `ed25519` | 0.035 | 0.050 | 0.111 | 0.148 |

## 4. End-to-End CLI Sign Execution

| Algorithm | Artifact Size | Median (ms) | P95 (ms) |
| :--- | :--- | :---: | :---: |
| `rsa-pss-sha256` | 1 KB | 176.466 | 228.974 |
| `rsa-pss-sha256` | 10 MB | 190.368 | 337.111 |
| `rsa-pss-sha256` | 50 MB | 224.029 | 240.559 |
| `ecdsa-p256-sha256` | 1 KB | 68.004 | 70.483 |
| `ecdsa-p256-sha256` | 10 MB | 78.477 | 112.827 |
| `ecdsa-p256-sha256` | 50 MB | 117.050 | 163.716 |
| `ed25519` | 1 KB | 68.177 | 78.765 |
| `ed25519` | 10 MB | 77.500 | 92.777 |
| `ed25519` | 50 MB | 118.707 | 131.648 |

## 4b. End-to-End CLI Verify Execution

| Algorithm | Artifact Size | Median (ms) | P95 (ms) |
| :--- | :--- | :---: | :---: |
| `rsa-pss-sha256` | 1 KB | 67.393 | 84.861 |
| `rsa-pss-sha256` | 10 MB | 77.110 | 79.944 |
| `rsa-pss-sha256` | 50 MB | 110.823 | 117.829 |
| `ecdsa-p256-sha256` | 1 KB | 67.605 | 83.049 |
| `ecdsa-p256-sha256` | 10 MB | 75.372 | 93.653 |
| `ecdsa-p256-sha256` | 50 MB | 112.676 | 122.675 |
| `ed25519` | 1 KB | 69.009 | 72.734 |
| `ed25519` | 10 MB | 78.253 | 91.493 |
| `ed25519` | 50 MB | 109.571 | 111.990 |

## 5. Component Sizes in Bytes

| Algorithm | Private Key DER (B) | Public Key DER (B) | Raw Signature (B) | Bundle JSON (B) |
| :--- | :---: | :---: | :---: | :---: |
| `rsa-pss-sha256` | 1795 | 422 | 384 | 794 |
| `ecdsa-p256-sha256` | 138 | 91 | 64 | 370 |
| `ed25519` | 48 | 44 | 64 | 370 |

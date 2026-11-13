# Video Demo Guide & Storyboard (Bonus 1)

This document provides the storyboard, speaking script outline, and demonstration checklist for the <=20 minute video demo required for Bonus 1 (+5 points).

## General Requirements
- **Platform**: YouTube (must be public or unlisted with public link, uploaded to `youtube.com`).
- **Duration**: Maximum 20 minutes.
- **Participation**: All group members must speak on-camera with introductions (`wajib oncam dan melakukan perkenalan`).

---

## Team Roster
- **Brian A. Hadian (13523048)**: Architecture, Cryptographic Profiles, Canonical Manifest Serialization, Signing Engine, Docker & CI/CD.
- **Andrew Isra Saputra DB (13523110)**: Trust Store Management, 8-Step Verification Pipeline, Signed SBOM (Bonus 3), Failure Analysis.

---

## Video Storyboard & Schedule

| Timestamp | Section | Speaker | Visual Asset / Screen Content |
| :---: | :--- | :---: | :--- |
| **00:00 - 01:30** | **Introduction & Overview** | Both | On-camera introduction of Brian and Andrew; project mission and Cytus II Nora theme. |
| **01:30 - 05:00** | **System Architecture & Cryptography** | Brian | Slides & Diagrams: RSA-PSS (3072-bit), ECDSA P-256 (raw `r \|\| s`), Ed25519 (PureEdDSA), canonical manifest serialization without BOM/spaces. |
| **05:00 - 08:30** | **Trust Store & Verification Pipeline** | Andrew | Slides & Code: Trust store JSON structure, atomic file write, 8-step verification pipeline (Table 2.8), error codes. |
| **08:30 - 12:30** | **Live CLI Demonstration (All 3 Algorithms)** | Brian | Terminal: `keygen`, `sign`, and inspect bundles for `rsa-pss-sha256`, `ecdsa-p256-sha256`, and `ed25519`. Show OpenSSL interoperability. |
| **12:30 - 16:00** | **Verification & Failure Testing (U01 - U14)** | Andrew | Terminal: Verification demo, artifact tampering (U02/U03), signature bit-flip (U05), trust failure (U06/U07), JSON output. |
| **16:00 - 18:30** | **Docker Container & CI/CD Pipeline** | Brian | GitHub Actions workflow run: Image pull by SHA-256 digest, `--network none` execution, non-root user UID/GID. |
| **18:30 - 19:30** | **Signed SBOM Demonstration (Bonus 3)** | Andrew | Terminal: `norasign sbom generate` & `norasign sbom verify`, artifact hash binding verification. |
| **19:30 - 20:00** | **Conclusion & Wrap-Up** | Both | Final remarks, repository links, documentation link. |

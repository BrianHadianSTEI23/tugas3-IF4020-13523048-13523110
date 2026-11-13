"""
Signed SBOM (Software Bill of Materials) module for NoraSign.
IF4020 Kriptografi Chapter 3 - Section 2.10 (Bonus 3).

Assigned to: Andrew Isra Saputra DB (NIM 13523110).

Specification Checklist for Component 5:
- SBOM format: JSON.
- SBOM is signed as a separate artifact using the same bundle format (minisign-bundle/v1).
- SBOM content MUST contain the exact SHA-256 hash of the release artifact it references.
- Commands:
  - sbom generate --artifact <path> --out <sbom.json>
  - sbom verify --artifact <artifact_path> --artifact-bundle <bundle.json> --sbom <sbom.json> --sbom-bundle <sbom_bundle.json> --trust-store <trust.json> --package <pkg> --version <ver>
- Checks:
  - Verifies artifact release bundle.
  - Verifies SBOM bundle.
  - Verifies cross-reference: SBOM artifact sha256 == release artifact sha256.
  - Rejects if SBOM content altered or artifact replaced.
"""

from typing import Any, Dict


def generate_sbom(artifact_path: str, out_path: str, package: str = "", version: str = "") -> Dict[str, Any]:
    """
    Generate JSON SBOM binding the artifact SHA-256 and metadata.
    Assigned to NIM 13523110.
    """
    raise NotImplementedError(
        "Component 5 (Signed SBOM Bonus) is assigned to Andrew Isra Saputra DB (NIM 13523110)."
    )


def verify_sbom(
    artifact_path: str,
    artifact_bundle_path: str,
    sbom_path: str,
    sbom_bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
    json_output: bool = False,
) -> Dict[str, Any]:
    """
    Verify both release artifact and SBOM bundles, ensuring cryptographic binding.
    Assigned to NIM 13523110.
    """
    raise NotImplementedError(
        "Component 5 (Signed SBOM Bonus) is assigned to Andrew Isra Saputra DB (NIM 13523110)."
    )

"""
Command Line Interface for NoraSign.
IF4020 Kriptografi Chapter 3 - Section 2.6 and Table 2.7.
"""

import argparse
import os
import sys
from typing import List, Optional

from norasign import __version__
from norasign.constants import (
    EXIT_SUCCESS,
    EXIT_USAGE_OR_IO_ERROR,
    SUPPORTED_ALGORITHMS,
)
from norasign.crypto import (
    calculate_keyid,
    load_private_key_pem,
    save_keypair_files,
    sign_message,
)
from norasign.bundle import create_bundle, serialize_bundle
from norasign.manifest import build_manifest


class NoraSignArgumentParser(argparse.ArgumentParser):
    """Custom parser ensuring exit code 2 on argument errors."""

    def error(self, message: str):
        sys.stderr.write(f"norasign error: {message}\n")
        sys.exit(EXIT_USAGE_OR_IO_ERROR)


def cmd_keygen(args: argparse.Namespace) -> int:
    """Handle `keygen` subcommand."""
    algorithm = args.algorithm
    out_prefix = args.out

    if algorithm not in SUPPORTED_ALGORITHMS:
        sys.stderr.write(
            f"Error: Unsupported algorithm '{algorithm}'. Must be one of {SUPPORTED_ALGORITHMS}\n"
        )
        return EXIT_USAGE_OR_IO_ERROR

    try:
        priv_path, pub_path, keyid = save_keypair_files(
            algorithm=algorithm,
            out_prefix=out_prefix,
            overwrite=args.force,
        )
    except FileExistsError as e:
        sys.stderr.write(f"Error: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR
    except Exception as e:
        sys.stderr.write(f"Error during key generation: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR

    print(f"Generated keypair for {algorithm}:")
    print(f"  Private key: {priv_path}")
    print(f"  Public key:  {pub_path}")
    print(f"  Fingerprint: {keyid}")
    return EXIT_SUCCESS


def cmd_sign(args: argparse.Namespace) -> int:
    """Handle `sign` subcommand."""
    file_path = args.file
    package_name = args.package
    version_str = args.version
    key_path = args.key
    out_bundle_path = args.out

    # 1. Check artifact file readability
    if not os.path.isfile(file_path):
        sys.stderr.write(f"Error: Artifact file not found or not readable: '{file_path}'\n")
        return EXIT_USAGE_OR_IO_ERROR

    # 2. Check private key file readability
    if not os.path.isfile(key_path):
        sys.stderr.write(f"Error: Private key file not found: '{key_path}'\n")
        return EXIT_USAGE_OR_IO_ERROR

    try:
        with open(key_path, "rb") as f:
            priv_pem = f.read()
        private_key, algorithm = load_private_key_pem(priv_pem)
    except Exception as e:
        sys.stderr.write(f"Error loading private key: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR

    # 3. Derive public key and calculate keyid
    try:
        public_key = private_key.public_key()
        keyid = calculate_keyid(public_key)
    except Exception as e:
        sys.stderr.write(f"Error calculating keyid from private key: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR

    # 4. Build release manifest and canonical bytes M
    try:
        _, canonical_manifest_bytes = build_manifest(
            artifact_path=file_path,
            package=package_name,
            version=version_str,
            algorithm=algorithm,
            keyid=keyid,
        )
    except Exception as e:
        sys.stderr.write(f"Error constructing release manifest: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR

    # 5. Sign manifest bytes M
    try:
        signature_bytes = sign_message(
            private_key=private_key,
            algorithm=algorithm,
            message=canonical_manifest_bytes,
        )
    except Exception as e:
        sys.stderr.write(f"Error signing manifest: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR

    # 6. Create bundle
    try:
        bundle_dict = create_bundle(
            manifest_bytes=canonical_manifest_bytes,
            signature_bytes=signature_bytes,
        )
        bundle_bytes = serialize_bundle(bundle_dict)
    except Exception as e:
        sys.stderr.write(f"Error serializing bundle: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR

    # 7. Write bundle to output path
    out_dir = os.path.dirname(out_bundle_path)
    if out_dir:
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            sys.stderr.write(f"Error creating output directory: {e}\n")
            return EXIT_USAGE_OR_IO_ERROR

    try:
        with open(out_bundle_path, "wb") as f:
            f.write(bundle_bytes)
    except Exception as e:
        sys.stderr.write(f"Error writing bundle file: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR

    print(f"Successfully signed release artifact '{file_path}'")
    print(f"  Package:   {package_name} v{version_str}")
    print(f"  Algorithm: {algorithm}")
    print(f"  Key ID:    {keyid}")
    print(f"  Bundle:    {out_bundle_path}")
    return EXIT_SUCCESS


def cmd_verify(args: argparse.Namespace) -> int:
    """Handle `verify` subcommand (delegated to Component 4)."""
    try:
        from norasign.verifier import verify_release
        result = verify_release(
            file_path=args.file,
            bundle_path=args.bundle,
            trust_store_path=args.trust_store,
            package=args.package,
            version=args.version,
            json_output=args.json,
        )
        # If verify_release returns a status dict:
        if isinstance(result, dict) and result.get("valid") is True:
            return EXIT_SUCCESS
        return 1
    except NotImplementedError as e:
        sys.stderr.write(f"Notice: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR
    except Exception as e:
        sys.stderr.write(f"Verification error: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR


def cmd_trust_add(args: argparse.Namespace) -> int:
    """Handle `trust add` subcommand (delegated to Component 3)."""
    try:
        from norasign.trust import trust_add
        trust_add(key_path=args.key, package=args.package, store_path=args.store)
        return EXIT_SUCCESS
    except NotImplementedError as e:
        sys.stderr.write(f"Notice: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR
    except Exception as e:
        sys.stderr.write(f"Trust add error: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR


def cmd_trust_list(args: argparse.Namespace) -> int:
    """Handle `trust list` subcommand (delegated to Component 3)."""
    try:
        from norasign.trust import trust_list
        trust_list(store_path=args.store)
        return EXIT_SUCCESS
    except NotImplementedError as e:
        sys.stderr.write(f"Notice: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR
    except Exception as e:
        sys.stderr.write(f"Trust list error: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR


def cmd_trust_remove(args: argparse.Namespace) -> int:
    """Handle `trust remove` subcommand (delegated to Component 3)."""
    try:
        from norasign.trust import trust_remove
        trust_remove(keyid=args.keyid, store_path=args.store)
        return EXIT_SUCCESS
    except NotImplementedError as e:
        sys.stderr.write(f"Notice: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR
    except Exception as e:
        sys.stderr.write(f"Trust remove error: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR


def cmd_sbom_generate(args: argparse.Namespace) -> int:
    """Handle `sbom generate` subcommand (delegated to Component 5)."""
    try:
        from norasign.sbom import generate_sbom
        generate_sbom(
            artifact_path=args.artifact,
            out_path=args.out,
            package=args.package or "",
            version=args.version or "",
        )
        return EXIT_SUCCESS
    except NotImplementedError as e:
        sys.stderr.write(f"Notice: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR
    except Exception as e:
        sys.stderr.write(f"SBOM generate error: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR


def cmd_sbom_verify(args: argparse.Namespace) -> int:
    """Handle `sbom verify` subcommand (delegated to Component 5)."""
    try:
        from norasign.sbom import verify_sbom
        result = verify_sbom(
            artifact_path=args.artifact,
            artifact_bundle_path=args.artifact_bundle,
            sbom_path=args.sbom,
            sbom_bundle_path=args.sbom_bundle,
            trust_store_path=args.trust_store,
            package=args.package,
            version=args.version,
            json_output=args.json,
        )
        if isinstance(result, dict) and result.get("valid") is True:
            return EXIT_SUCCESS
        return 1
    except NotImplementedError as e:
        sys.stderr.write(f"Notice: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR
    except Exception as e:
        sys.stderr.write(f"SBOM verify error: {e}\n")
        return EXIT_USAGE_OR_IO_ERROR


def build_parser() -> NoraSignArgumentParser:
    """Build and configure argparse argument hierarchy."""
    parser = NoraSignArgumentParser(
        prog="norasign",
        description="NoraSign: Cryptographic Software Release Signing and Verification CLI.",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"norasign {__version__}",
    )

    subparsers = parser.add_subparsers(dest="subcommand", title="subcommands", required=True)

    # 1. keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate cryptographic keypair")
    p_keygen.add_argument(
        "--algorithm",
        required=True,
        choices=SUPPORTED_ALGORITHMS,
        help="Algorithm profile (rsa-pss-sha256, ecdsa-p256-sha256, ed25519)",
    )
    p_keygen.add_argument(
        "--out",
        required=True,
        help="Prefix path for output files (<prefix>.key.pem and <prefix>.pub.pem)",
    )
    p_keygen.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Explicitly allow overwriting existing private key file",
    )
    p_keygen.set_defaults(func=cmd_keygen)

    # 2. sign
    p_sign = subparsers.add_parser("sign", help="Sign a release artifact and create bundle")
    p_sign.add_argument("--file", required=True, help="Path to release artifact file")
    p_sign.add_argument("--package", required=True, help="Package name")
    p_sign.add_argument("--version", required=True, help="Release version")
    p_sign.add_argument("--key", required=True, help="Path to signer private key PEM")
    p_sign.add_argument("--out", required=True, help="Path for output bundle JSON")
    p_sign.set_defaults(func=cmd_sign)

    # 3. verify
    p_verify = subparsers.add_parser("verify", help="Verify a release artifact against bundle and trust store")
    p_verify.add_argument("--file", required=True, help="Path to release artifact file")
    p_verify.add_argument("--bundle", required=True, help="Path to release bundle JSON")
    p_verify.add_argument("--trust-store", required=True, help="Path to trust store JSON")
    p_verify.add_argument("--package", required=True, help="Expected package name")
    p_verify.add_argument("--version", required=True, help="Expected version")
    p_verify.add_argument("--json", action="store_true", help="Format output as JSON on stdout")
    p_verify.set_defaults(func=cmd_verify)

    # 4. trust
    p_trust = subparsers.add_parser("trust", help="Manage trust store")
    trust_sub = p_trust.add_subparsers(dest="trust_action", title="trust actions", required=True)

    # trust add
    p_trust_add = trust_sub.add_parser("add", help="Add public key authorization to trust store")
    p_trust_add.add_argument("--key", required=True, help="Path to public key PEM")
    p_trust_add.add_argument("--package", required=True, help="Package name authorized for this key")
    p_trust_add.add_argument("--store", required=True, help="Path to trust store JSON")
    p_trust_add.set_defaults(func=cmd_trust_add)

    # trust list
    p_trust_list = trust_sub.add_parser("list", help="List authorized keys in trust store")
    p_trust_list.add_argument("--store", required=True, help="Path to trust store JSON")
    p_trust_list.set_defaults(func=cmd_trust_list)

    # trust remove
    p_trust_remove = trust_sub.add_parser("remove", help="Remove key from trust store by keyid")
    p_trust_remove.add_argument("--keyid", required=True, help="Fingerprint of key to remove")
    p_trust_remove.add_argument("--store", required=True, help="Path to trust store JSON")
    p_trust_remove.set_defaults(func=cmd_trust_remove)

    # 5. sbom (Bonus 3)
    p_sbom = subparsers.add_parser("sbom", help="SBOM signing and verification (Bonus 3)")
    sbom_sub = p_sbom.add_subparsers(dest="sbom_action", title="sbom actions", required=True)

    # sbom generate
    p_sbom_gen = sbom_sub.add_parser("generate", help="Generate JSON SBOM referencing artifact hash")
    p_sbom_gen.add_argument("--artifact", required=True, help="Path to release artifact")
    p_sbom_gen.add_argument("--out", required=True, help="Output path for SBOM JSON")
    p_sbom_gen.add_argument("--package", default="", help="Package name")
    p_sbom_gen.add_argument("--version", default="", help="Release version")
    p_sbom_gen.set_defaults(func=cmd_sbom_generate)

    # sbom verify
    p_sbom_ver = sbom_sub.add_parser("verify", help="Verify release artifact and SBOM dual bundles")
    p_sbom_ver.add_argument("--artifact", required=True, help="Path to release artifact")
    p_sbom_ver.add_argument("--artifact-bundle", required=True, help="Path to release bundle JSON")
    p_sbom_ver.add_argument("--sbom", required=True, help="Path to SBOM JSON")
    p_sbom_ver.add_argument("--sbom-bundle", required=True, help="Path to SBOM bundle JSON")
    p_sbom_ver.add_argument("--trust-store", required=True, help="Path to trust store JSON")
    p_sbom_ver.add_argument("--package", required=True, help="Expected package name")
    p_sbom_ver.add_argument("--version", required=True, help="Expected version")
    p_sbom_ver.add_argument("--json", action="store_true", help="Format output as JSON on stdout")
    p_sbom_ver.set_defaults(func=cmd_sbom_verify)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

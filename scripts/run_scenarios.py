#!/usr/bin/env python3
"""
Build and run test scenarios U01-U14 (Table 2.11), extra negative cases, and SBOM cases.
Every scenario gets its own folder with input files, the exact command, the expected
status, stdout JSON, and exit code. A summary is written to results.md and results.json.

Usage: python scripts/run_scenarios.py [--out test_cases]
"""

import argparse
import base64
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from norasign.constants import ALG_ECDSA_P256, ALG_ED25519, ALG_RSA_PSS  # noqa: E402
from norasign.crypto import calculate_keyid, load_private_key_pem, sign_message  # noqa: E402
from norasign.manifest import serialize_manifest  # noqa: E402

ALGOS = [ALG_RSA_PSS, ALG_ECDSA_P256, ALG_ED25519]
SHORT = {ALG_RSA_PSS: "rsa", ALG_ECDSA_P256: "ecdsa", ALG_ED25519: "ed25519"}
PKG, VER = "contoh-app", "1.0.0"
TEXT = "NoraSign test artifact\nbaris kedua\n".encode("utf-8")
BINARY = bytes(range(256)) * 64


class Runner:
    def __init__(self, out: Path):
        self.out = out
        self.results = []
        self.env = dict(os.environ, PYTHONPATH=str(ROOT))

    @staticmethod
    def rel(args, cwd: Path):
        return [os.path.relpath(a, cwd) if isinstance(a, Path) else str(a) for a in args]

    def cli(self, *args, cwd: Path):
        cmd = [sys.executable, "-m", "norasign.cli", *self.rel(args, cwd)]
        proc = subprocess.run(cmd, cwd=cwd, env=self.env, capture_output=True, text=True)
        return proc

    def setup(self, *args, cwd: Path):
        proc = self.cli(*args, cwd=cwd)
        if proc.returncode != 0:
            raise RuntimeError(f"setup failed: {args}\n{proc.stderr}")
        return proc

    def verify(self, sid, title, cwd, expected, file, bundle, trust, package=PKG, version=VER, algo="-", note=""):
        args = ["verify", "--file", file, "--bundle", bundle, "--trust-store", trust,
                "--package", package, "--version", version, "--json"]
        proc = self.cli(*args, cwd=cwd)
        self._record(sid, title, cwd, expected, args, proc, algo, note)
        return proc

    def sbom_verify(self, sid, title, cwd, expected, file, bundle, sbom, sbom_bundle, trust, note=""):
        args = ["sbom", "verify", "--artifact", file, "--artifact-bundle", bundle, "--sbom", sbom,
                "--sbom-bundle", sbom_bundle, "--trust-store", trust, "--package", PKG, "--version", VER, "--json"]
        proc = self.cli(*args, cwd=cwd)
        self._record(sid, title, cwd, expected, args, proc, "ed25519", note)
        return proc

    def _record(self, sid, title, cwd, expected, args, proc, algo, note):
        try:
            out = json.loads(proc.stdout)
            status = out["status"]
        except (ValueError, KeyError):
            out, status = None, "NO_JSON"
        expected_exit = 0 if expected == "OK" else (2 if expected == "INPUT_ERROR" else 1)
        passed = status == expected and proc.returncode == expected_exit
        tag = f"{sid}-{len([r for r in self.results if r['id'] == sid]) + 1}"
        (cwd / f"{tag}.cmd.txt").write_text("norasign " + " ".join(shlex.quote(a) for a in self.rel(args, cwd)) + "\n")
        (cwd / f"{tag}.stdout.json").write_text(proc.stdout)
        (cwd / f"{tag}.stderr.txt").write_text(proc.stderr)
        self.results.append({
            "id": sid, "case": tag, "title": title, "algorithm": algo, "expected": expected,
            "actual": status, "exit_code": proc.returncode, "expected_exit": expected_exit,
            "pass": passed, "message": (out or {}).get("message", proc.stderr.strip()), "note": note,
            "dir": str(cwd.relative_to(self.out)),
        })
        mark = "PASS" if passed else "FAIL"
        print(f"[{mark}] {tag:8s} {algo:18s} expected={expected:22s} actual={status:22s} exit={proc.returncode}  {title}")


def read_bundle(path: Path):
    b = json.loads(path.read_text())
    return b, base64.b64decode(b["manifest_b64"]), base64.b64decode(b["signature_b64"])


def write_bundle(path: Path, manifest_bytes: bytes, sig: bytes):
    path.write_text(json.dumps({
        "schema": "minisign-bundle/v1",
        "manifest_b64": base64.b64encode(manifest_bytes).decode(),
        "signature_b64": base64.b64encode(sig).decode(),
    }, indent=2) + "\n")


def manifest_dict(manifest_bytes: bytes):
    return json.loads(manifest_bytes)


def sign_raw(key_path: Path, manifest_bytes: bytes) -> bytes:
    key, algo = load_private_key_pem(key_path.read_bytes())
    return sign_message(key, algo, manifest_bytes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "test_cases"))
    args = ap.parse_args()
    out = Path(args.out).resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    r = Runner(out)

    keys = out / "keys"
    keys.mkdir()
    for algo in ALGOS:
        r.setup("keygen", "--algorithm", algo, "--out", keys / f"publisher_{SHORT[algo]}", cwd=out)
    r.setup("keygen", "--algorithm", ALG_ED25519, "--out", keys / "attacker_ed25519", cwd=out)
    r.setup("keygen", "--algorithm", ALG_ED25519, "--out", keys / "otherpkg_ed25519", cwd=out)

    trust = out / "trust.json"
    for algo in ALGOS:
        r.setup("trust", "add", "--key", keys / f"publisher_{SHORT[algo]}.pub.pem", "--package", PKG, "--store", trust, cwd=out)
    ed_key = keys / "publisher_ed25519.key.pem"

    def scenario_dir(name):
        d = out / name
        d.mkdir(exist_ok=True)
        return d

    def signed(d: Path, name: str, data: bytes, key: Path, version=VER, bundle_name=None):
        art = d / name
        art.write_bytes(data)
        bundle = d / (bundle_name or f"{name}.bundle.json")
        r.setup("sign", "--file", art, "--package", PKG, "--version", version, "--key", key, "--out", bundle, cwd=d)
        return art, bundle

    # U01
    d = scenario_dir("U01")
    for algo in ALGOS:
        k = keys / f"publisher_{SHORT[algo]}.key.pem"
        for label, fname, data in (("teks", "notes.txt", TEXT), ("biner", "app.bin", BINARY), ("kosong", "empty.dat", b"")):
            sub = scenario_dir(f"U01/{SHORT[algo]}_{label}")
            art, bundle = signed(sub, fname, data, k)
            r.verify("U01", f"Berkas {label} valid", sub, "OK", art, bundle, trust, algo=algo)

    # U02
    d = scenario_dir("U02")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    data = bytearray(art.read_bytes())
    data[100] ^= 0xFF
    art.write_bytes(bytes(data))
    r.verify("U02", "Satu byte artefak diubah (ukuran & nama tetap)", d, "ARTIFACT_MISMATCH", art, bundle, trust, algo=ALG_ED25519)

    # U03
    d = scenario_dir("U03")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    art.write_bytes(BINARY + b"\x00")
    r.verify("U03", "Satu byte ditambahkan ke artefak", d, "ARTIFACT_MISMATCH", art, bundle, trust, algo=ALG_ED25519)
    art.write_bytes(BINARY[:-1])
    r.verify("U03", "Satu byte dihapus dari artefak", d, "ARTIFACT_MISMATCH", art, bundle, trust, algo=ALG_ED25519)

    # U04
    d = scenario_dir("U04")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    _, m, sig = read_bundle(bundle)
    md = manifest_dict(m)
    md["version"] = "1.0.1"
    tampered = d / "tampered.bundle.json"
    write_bundle(tampered, serialize_manifest(md), sig)
    r.verify("U04", "Versi manifest diubah (kanonik), tanda tangan lama", d, "INVALID_SIGNATURE", art, tampered, trust,
             version="1.0.1", algo=ALG_ED25519)

    # U05
    d = scenario_dir("U05")
    for algo in ALGOS:
        k = keys / f"publisher_{SHORT[algo]}.key.pem"
        art, bundle = signed(d, f"app_{SHORT[algo]}.bin", BINARY, k)
        _, m, sig = read_bundle(bundle)
        flipped = bytearray(sig)
        flipped[len(sig) // 2] ^= 0x01
        tb = d / f"{SHORT[algo]}.bitflip.bundle.json"
        write_bundle(tb, m, bytes(flipped))
        r.verify("U05", "Satu bit tanda tangan dibalik", d, "INVALID_SIGNATURE", art, tb, trust, algo=algo)

    # U06
    d = scenario_dir("U06")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    empty = d / "empty-trust.json"
    empty.write_text('{\n  "schema": "minisign-trust/v1",\n  "keys": []\n}\n')
    r.verify("U06", "Trust store kosong", d, "KEY_NOT_TRUSTED", art, bundle, empty, algo=ALG_ED25519)
    removed = d / "removed-trust.json"
    shutil.copy(trust, removed)
    ed_keyid = calculate_keyid(load_private_key_pem(ed_key.read_bytes())[0].public_key())
    r.setup("trust", "remove", "--keyid", ed_keyid, "--store", removed, cwd=d)
    r.verify("U06", "Kunci penerbit dihapus via trust remove", d, "KEY_NOT_TRUSTED", art, bundle, removed, algo=ALG_ED25519)

    # U07
    d = scenario_dir("U07")
    other_trust = d / "trust-other-package.json"
    r.setup("trust", "add", "--key", keys / "otherpkg_ed25519.pub.pem", "--package", "paket-lain", "--store", other_trust, cwd=d)
    art, bundle = signed(d, "app.bin", BINARY, keys / "otherpkg_ed25519.key.pem")
    r.verify("U07", "Kunci hanya diizinkan untuk paket lain", d, "KEY_NOT_TRUSTED", art, bundle, other_trust, algo=ALG_ED25519)

    # U08
    d = scenario_dir("U08")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    r.verify("U08", "Versi yang diharapkan berbeda dari manifest", d, "METADATA_MISMATCH", art, bundle, trust,
             version="2.0.0", algo=ALG_ED25519)

    # U09
    d = scenario_dir("U09")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    renamed = d / "app-renamed.bin"
    shutil.copy(art, renamed)
    r.verify("U09", "Nama berkas artefak diubah, isi sama", d, "METADATA_MISMATCH", renamed, bundle, trust, algo=ALG_ED25519)

    # U10
    d = scenario_dir("U10")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    raw_bundle, m, sig = read_bundle(bundle)
    m_b64, s_b64 = raw_bundle["manifest_b64"], raw_bundle["signature_b64"]

    p = d / "dup-field-bundle.json"
    p.write_text('{"schema":"minisign-bundle/v1","manifest_b64":"%s","manifest_b64":"%s","signature_b64":"%s"}' % (m_b64, m_b64, s_b64))
    r.verify("U10", "Field duplikat pada bundle", d, "FORMAT_ERROR", art, p, trust, algo=ALG_ED25519)

    dup_manifest = m.replace(b'"version":"1.0.0"', b'"version":"1.0.0","version":"1.0.0"')
    p = d / "dup-field-manifest.json"
    write_bundle(p, dup_manifest, sign_raw(ed_key, dup_manifest))
    r.verify("U10", "Field duplikat pada manifest (ditandatangani ulang)", d, "FORMAT_ERROR", art, p, trust, algo=ALG_ED25519)

    md = manifest_dict(m)
    md["artifact"]["size"] = str(md["artifact"]["size"])
    wrong = json.dumps(md, separators=(",", ":")).encode()
    p = d / "wrong-type-size-string.json"
    write_bundle(p, wrong, sign_raw(ed_key, wrong))
    r.verify("U10", "Tipe salah: artifact.size berupa string", d, "FORMAT_ERROR", art, p, trust, algo=ALG_ED25519)

    md = manifest_dict(m)
    md["artifact"]["size"] = True
    wrong = json.dumps(md, separators=(",", ":")).encode()
    p = d / "wrong-type-size-bool.json"
    write_bundle(p, wrong, sign_raw(ed_key, wrong))
    r.verify("U10", "Tipe salah: artifact.size berupa boolean", d, "FORMAT_ERROR", art, p, trust, algo=ALG_ED25519)

    p = d / "wrong-type-signature.json"
    p.write_text(json.dumps({"schema": "minisign-bundle/v1", "manifest_b64": m_b64, "signature_b64": 12345}))
    r.verify("U10", "Tipe salah: signature_b64 berupa integer", d, "FORMAT_ERROR", art, p, trust, algo=ALG_ED25519)

    for label, bad in (
        ("karakter-ilegal", s_b64[:-4] + "-_=="),
        ("tanpa-padding", s_b64.rstrip("=")),
        ("whitespace", s_b64[:10] + " " + s_b64[10:]),
        ("url-safe", "-" + m_b64[1:]),
    ):
        p = d / f"base64-{label}.json"
        field = "manifest_b64" if label == "url-safe" else "signature_b64"
        doc = {"schema": "minisign-bundle/v1", "manifest_b64": m_b64, "signature_b64": s_b64}
        doc[field] = bad
        p.write_text(json.dumps(doc))
        r.verify("U10", f"Base64 tidak valid ({label})", d, "FORMAT_ERROR", art, p, trust, algo=ALG_ED25519)

    big = m[:-1] + b"," + b'"x":"' + b"A" * 17000 + b'"}'
    p = d / "manifest-too-large.json"
    write_bundle(p, big, sign_raw(ed_key, big))
    r.verify("U10", "Manifest melebihi 16 KiB", d, "FORMAT_ERROR", art, p, trust, algo=ALG_ED25519)

    md = manifest_dict(m)
    md["extra"] = "x"
    extra = json.dumps(md, separators=(",", ":")).encode()
    p = d / "manifest-extra-field.json"
    write_bundle(p, extra, sign_raw(ed_key, extra))
    r.verify("U10", "Field tambahan pada manifest", d, "FORMAT_ERROR", art, p, trust, algo=ALG_ED25519)

    pretty = json.dumps(manifest_dict(m), indent=1).encode()
    p = d / "manifest-non-canonical.json"
    write_bundle(p, pretty, sign_raw(ed_key, pretty))
    r.verify("U10", "Manifest tidak kanonik (white space), sah ditandatangani", d, "FORMAT_ERROR", art, p, trust, algo=ALG_ED25519)

    tdoc = json.loads(trust.read_text())
    tdoc["keys"][0]["keyid"] = "0" * 64
    p = d / "trust-wrong-fingerprint.json"
    p.write_text(json.dumps(tdoc, indent=2))
    r.verify("U10", "Trust store: keyid tidak cocok dengan public_key_pem", d, "FORMAT_ERROR", art, bundle, p, algo=ALG_ED25519)

    tdoc = json.loads(trust.read_text())
    for e in tdoc["keys"]:
        if e["algorithm"] == ALG_ED25519:
            e["algorithm"] = ALG_ECDSA_P256
    p = d / "trust-profile-mismatch-key-type.json"
    p.write_text(json.dumps(tdoc, indent=2))
    r.verify("U10", "Trust store: profil tidak sesuai tipe kunci", d, "FORMAT_ERROR", art, bundle, p, algo=ALG_ED25519)

    tdoc = json.loads(trust.read_text())
    tdoc["keys"][0]["packages"] = ["*"]
    p = d / "trust-wildcard.json"
    p.write_text(json.dumps(tdoc, indent=2))
    r.verify("U10", "Trust store: wildcard pada packages", d, "FORMAT_ERROR", art, bundle, p, algo=ALG_ED25519)

    # U11
    d = scenario_dir("U11")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    _, m, _ = read_bundle(bundle)
    md = manifest_dict(m)
    md["algorithm"] = "ed448"
    unsup = serialize_manifest(md)
    p = d / "unsupported-algorithm.bundle.json"
    write_bundle(p, unsup, sign_raw(ed_key, unsup))
    r.verify("U11", "algorithm = 'ed448' (tidak didukung)", d, "UNSUPPORTED_ALGORITHM", art, p, trust, algo="ed448")

    # U12
    d = scenario_dir("U12")
    art, bundle = signed(d, "app.bin", BINARY, keys / "attacker_ed25519.key.pem")
    r.verify("U12", "Ditandatangani kunci lain (profil sama) di luar trust store", d, "KEY_NOT_TRUSTED", art, bundle, trust,
             algo=ALG_ED25519)

    # U13
    d = scenario_dir("U13")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    b, _, _ = read_bundle(bundle)
    p = d / "reformatted.bundle.json"
    p.write_text('\n\n  {   "signature_b64" :\t"%s" ,\n"manifest_b64":   "%s",\r\n "schema":"minisign-bundle/v1"   }\n\n'
                 % (b["signature_b64"], b["manifest_b64"]))
    r.verify("U13", "White space & urutan field bundle diubah", d, "OK", art, p, trust, algo=ALG_ED25519)

    # U14
    d = scenario_dir("U14")
    u14 = {}
    for algo in ALGOS:
        k = keys / f"publisher_{SHORT[algo]}.key.pem"
        art = d / f"app_{SHORT[algo]}.bin"
        art.write_bytes(BINARY)
        sigs = []
        for i in (1, 2):
            bundle = d / f"{SHORT[algo]}.sign{i}.bundle.json"
            r.setup("sign", "--file", art, "--package", PKG, "--version", VER, "--key", k, "--out", bundle, cwd=d)
            _, m, sig = read_bundle(bundle)
            sigs.append((m, sig))
            r.verify("U14", f"Penandatanganan ke-{i} manifest identik", d, "OK", art, bundle, trust, algo=algo)
        same_manifest = sigs[0][0] == sigs[1][0]
        same_sig = sigs[0][1] == sigs[1][1]
        u14[algo] = {"manifest_identical": same_manifest, "signature_identical": same_sig,
                     "sig1_b64": base64.b64encode(sigs[0][1]).decode(), "sig2_b64": base64.b64encode(sigs[1][1]).decode()}
        print(f"       U14 {algo:18s} manifest identik={same_manifest} signature identik={same_sig}")
    (d / "comparison.json").write_text(json.dumps(u14, indent=2) + "\n")

    # Extra negative cases
    d = scenario_dir("X01")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    _, m, sig = read_bundle(bundle)
    md = manifest_dict(m)
    md["algorithm"] = ALG_ECDSA_P256
    mm = serialize_manifest(md)
    p = d / "profile-mismatch.bundle.json"
    write_bundle(p, mm, sig)
    r.verify("X01", "Profil manifest (ecdsa) berbeda dari profil kunci tepercaya (ed25519)", d, "KEY_NOT_TRUSTED",
             art, p, trust, algo=ALG_ECDSA_P256)

    d = scenario_dir("X02")
    ec_key = keys / "publisher_ecdsa.key.pem"
    art, bundle = signed(d, "app.bin", BINARY, ec_key)
    _, m, sig = read_bundle(bundle)
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    for label, bad in (("r-nol", b"\x00" * 32 + sig[32:]), ("s-sama-n", sig[:32] + n.to_bytes(32, "big"))):
        p = d / f"ecdsa-{label}.bundle.json"
        write_bundle(p, m, bad)
        r.verify("X02", f"ECDSA r||s di luar domain ({label})", d, "INVALID_SIGNATURE", art, p, trust, algo=ALG_ECDSA_P256)
    p = d / "ecdsa-der-signature.bundle.json"
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    write_bundle(p, m, der)
    r.verify("X02", "Tanda tangan ECDSA format DER (bukan r||s)", d, "INVALID_SIGNATURE", art, p, trust, algo=ALG_ECDSA_P256)

    d = scenario_dir("X03")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    r.verify("X03", "Berkas artefak tidak tersedia", d, "INPUT_ERROR", d / "missing.bin", bundle, trust, algo=ALG_ED25519)
    r.verify("X03", "Trust store tidak tersedia", d, "INPUT_ERROR", art, bundle, d / "missing-trust.json", algo=ALG_ED25519)
    (d / "corrupt-trust.json").write_text('{"schema":"minisign-trust/v1","keys":[')
    r.verify("X03", "Trust store rusak (JSON terpotong)", d, "FORMAT_ERROR", art, bundle, d / "corrupt-trust.json", algo=ALG_ED25519)

    # SBOM (Bonus 3)
    d = scenario_dir("S01")
    art, bundle = signed(d, "app.bin", BINARY, ed_key)
    sbom = d / "app.sbom.json"
    r.setup("sbom", "generate", "--artifact", art, "--package", PKG, "--version", VER,
            "--component", "cryptography@46.0.0", "--out", sbom, cwd=d)
    sbom_bundle = d / "app.sbom.bundle.json"
    r.setup("sbom", "sign", "--sbom", sbom, "--key", ed_key, "--out", sbom_bundle, cwd=d)
    r.sbom_verify("S01", "SBOM dan rilis sah, hash terikat", d, "OK", art, bundle, sbom, sbom_bundle, trust)

    d = scenario_dir("S02")
    for f in ("app.bin", "app.bin.bundle.json", "app.sbom.json", "app.sbom.bundle.json"):
        shutil.copy(out / "S01" / f, d / f)
    sdoc = json.loads((d / "app.sbom.json").read_text())
    sdoc["components"].append({"type": "library", "name": "malicious-lib", "version": "6.6.6"})
    (d / "app.sbom.json").write_text(json.dumps(sdoc, indent=2) + "\n")
    r.sbom_verify("S02", "Isi SBOM diubah setelah ditandatangani", d, "ARTIFACT_MISMATCH", d / "app.bin",
                  d / "app.bin.bundle.json", d / "app.sbom.json", d / "app.sbom.bundle.json", trust,
                  note="stage sbom")

    d = scenario_dir("S03")
    for f in ("app.bin", "app.bin.bundle.json", "app.sbom.json", "app.sbom.bundle.json"):
        shutil.copy(out / "S01" / f, d / f)
    (d / "app.bin").write_bytes(b"artefak pengganti" + BINARY)
    r.sbom_verify("S03", "Artefak rilis diganti tanpa tanda tangan baru", d, "ARTIFACT_MISMATCH", d / "app.bin",
                  d / "app.bin.bundle.json", d / "app.sbom.json", d / "app.sbom.bundle.json", trust,
                  note="stage release")

    d = scenario_dir("S04")
    shutil.copy(out / "S01" / "app.sbom.json", d / "app.sbom.json")
    shutil.copy(out / "S01" / "app.sbom.bundle.json", d / "app.sbom.bundle.json")
    art, bundle = signed(d, "app.bin", b"artefak rilis baru" + BINARY, ed_key)
    r.sbom_verify("S04", "Artefak diganti & ditandatangani ulang, SBOM lama dipakai", d, "SBOM_BINDING_MISMATCH",
                  art, bundle, d / "app.sbom.json", d / "app.sbom.bundle.json", trust, note="stage binding")

    passed = sum(1 for x in r.results if x["pass"])
    (out / "results.json").write_text(json.dumps({"passed": passed, "total": len(r.results), "u14": u14,
                                                    "results": r.results}, indent=2) + "\n")
    with open(out / "results.md", "w") as f:
        f.write(f"# Hasil Pengujian Skenario\n\nLulus {passed}/{len(r.results)} kasus.\n\n")
        f.write("| Kasus | Profil | Skenario | Diharapkan | Hasil | Exit | Lulus |\n|---|---|---|---|---|---|---|\n")
        for x in r.results:
            f.write(f"| {x['case']} | {x['algorithm']} | {x['title']} | {x['expected']} | {x['actual']} | "
                    f"{x['exit_code']} | {'Ya' if x['pass'] else 'Tidak'} |\n")
        f.write("\n## U14 Perbandingan Tanda Tangan\n\n| Profil | Manifest identik | Tanda tangan identik |\n|---|---|---|\n")
        for algo, v in u14.items():
            f.write(f"| {algo} | {v['manifest_identical']} | {v['signature_identical']} |\n")
    print(f"\n{passed}/{len(r.results)} cases passed. Results in {out}")
    return 0 if passed == len(r.results) else 1


if __name__ == "__main__":
    sys.exit(main())

# Hasil Pengujian Skenario

Lulus 56/56 kasus.

| Kasus | Profil | Skenario | Diharapkan | Hasil | Exit | Lulus |
|---|---|---|---|---|---|---|
| U01-1 | rsa-pss-sha256 | Berkas teks valid | OK | OK | 0 | Ya |
| U01-2 | rsa-pss-sha256 | Berkas biner valid | OK | OK | 0 | Ya |
| U01-3 | rsa-pss-sha256 | Berkas kosong valid | OK | OK | 0 | Ya |
| U01-4 | ecdsa-p256-sha256 | Berkas teks valid | OK | OK | 0 | Ya |
| U01-5 | ecdsa-p256-sha256 | Berkas biner valid | OK | OK | 0 | Ya |
| U01-6 | ecdsa-p256-sha256 | Berkas kosong valid | OK | OK | 0 | Ya |
| U01-7 | ed25519 | Berkas teks valid | OK | OK | 0 | Ya |
| U01-8 | ed25519 | Berkas biner valid | OK | OK | 0 | Ya |
| U01-9 | ed25519 | Berkas kosong valid | OK | OK | 0 | Ya |
| U02-1 | ed25519 | Satu byte artefak diubah (ukuran & nama tetap) | ARTIFACT_MISMATCH | ARTIFACT_MISMATCH | 1 | Ya |
| U03-1 | ed25519 | Satu byte ditambahkan ke artefak | ARTIFACT_MISMATCH | ARTIFACT_MISMATCH | 1 | Ya |
| U03-2 | ed25519 | Satu byte dihapus dari artefak | ARTIFACT_MISMATCH | ARTIFACT_MISMATCH | 1 | Ya |
| U04-1 | ed25519 | Versi manifest diubah (kanonik), tanda tangan lama | INVALID_SIGNATURE | INVALID_SIGNATURE | 1 | Ya |
| U05-1 | rsa-pss-sha256 | Satu bit tanda tangan dibalik | INVALID_SIGNATURE | INVALID_SIGNATURE | 1 | Ya |
| U05-2 | ecdsa-p256-sha256 | Satu bit tanda tangan dibalik | INVALID_SIGNATURE | INVALID_SIGNATURE | 1 | Ya |
| U05-3 | ed25519 | Satu bit tanda tangan dibalik | INVALID_SIGNATURE | INVALID_SIGNATURE | 1 | Ya |
| U06-1 | ed25519 | Trust store kosong | KEY_NOT_TRUSTED | KEY_NOT_TRUSTED | 1 | Ya |
| U06-2 | ed25519 | Kunci penerbit dihapus via trust remove | KEY_NOT_TRUSTED | KEY_NOT_TRUSTED | 1 | Ya |
| U07-1 | ed25519 | Kunci hanya diizinkan untuk paket lain | KEY_NOT_TRUSTED | KEY_NOT_TRUSTED | 1 | Ya |
| U08-1 | ed25519 | Versi yang diharapkan berbeda dari manifest | METADATA_MISMATCH | METADATA_MISMATCH | 1 | Ya |
| U09-1 | ed25519 | Nama berkas artefak diubah, isi sama | METADATA_MISMATCH | METADATA_MISMATCH | 1 | Ya |
| U10-1 | ed25519 | Field duplikat pada bundle | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-2 | ed25519 | Field duplikat pada manifest (ditandatangani ulang) | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-3 | ed25519 | Tipe salah: artifact.size berupa string | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-4 | ed25519 | Tipe salah: artifact.size berupa boolean | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-5 | ed25519 | Tipe salah: signature_b64 berupa integer | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-6 | ed25519 | Base64 tidak valid (karakter-ilegal) | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-7 | ed25519 | Base64 tidak valid (tanpa-padding) | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-8 | ed25519 | Base64 tidak valid (whitespace) | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-9 | ed25519 | Base64 tidak valid (url-safe) | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-10 | ed25519 | Manifest melebihi 16 KiB | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-11 | ed25519 | Field tambahan pada manifest | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-12 | ed25519 | Manifest tidak kanonik (white space), sah ditandatangani | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-13 | ed25519 | Trust store: keyid tidak cocok dengan public_key_pem | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-14 | ed25519 | Trust store: profil tidak sesuai tipe kunci | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U10-15 | ed25519 | Trust store: wildcard pada packages | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| U11-1 | ed448 | algorithm = 'ed448' (tidak didukung) | UNSUPPORTED_ALGORITHM | UNSUPPORTED_ALGORITHM | 1 | Ya |
| U12-1 | ed25519 | Ditandatangani kunci lain (profil sama) di luar trust store | KEY_NOT_TRUSTED | KEY_NOT_TRUSTED | 1 | Ya |
| U13-1 | ed25519 | White space & urutan field bundle diubah | OK | OK | 0 | Ya |
| U14-1 | rsa-pss-sha256 | Penandatanganan ke-1 manifest identik | OK | OK | 0 | Ya |
| U14-2 | rsa-pss-sha256 | Penandatanganan ke-2 manifest identik | OK | OK | 0 | Ya |
| U14-3 | ecdsa-p256-sha256 | Penandatanganan ke-1 manifest identik | OK | OK | 0 | Ya |
| U14-4 | ecdsa-p256-sha256 | Penandatanganan ke-2 manifest identik | OK | OK | 0 | Ya |
| U14-5 | ed25519 | Penandatanganan ke-1 manifest identik | OK | OK | 0 | Ya |
| U14-6 | ed25519 | Penandatanganan ke-2 manifest identik | OK | OK | 0 | Ya |
| X01-1 | ecdsa-p256-sha256 | Profil manifest (ecdsa) berbeda dari profil kunci tepercaya (ed25519) | KEY_NOT_TRUSTED | KEY_NOT_TRUSTED | 1 | Ya |
| X02-1 | ecdsa-p256-sha256 | ECDSA r||s di luar domain (r-nol) | INVALID_SIGNATURE | INVALID_SIGNATURE | 1 | Ya |
| X02-2 | ecdsa-p256-sha256 | ECDSA r||s di luar domain (s-sama-n) | INVALID_SIGNATURE | INVALID_SIGNATURE | 1 | Ya |
| X02-3 | ecdsa-p256-sha256 | Tanda tangan ECDSA format DER (bukan r||s) | INVALID_SIGNATURE | INVALID_SIGNATURE | 1 | Ya |
| X03-1 | ed25519 | Berkas artefak tidak tersedia | INPUT_ERROR | INPUT_ERROR | 2 | Ya |
| X03-2 | ed25519 | Trust store tidak tersedia | INPUT_ERROR | INPUT_ERROR | 2 | Ya |
| X03-3 | ed25519 | Trust store rusak (JSON terpotong) | FORMAT_ERROR | FORMAT_ERROR | 1 | Ya |
| S01-1 | ed25519 | SBOM dan rilis sah, hash terikat | OK | OK | 0 | Ya |
| S02-1 | ed25519 | Isi SBOM diubah setelah ditandatangani | ARTIFACT_MISMATCH | ARTIFACT_MISMATCH | 1 | Ya |
| S03-1 | ed25519 | Artefak rilis diganti tanpa tanda tangan baru | ARTIFACT_MISMATCH | ARTIFACT_MISMATCH | 1 | Ya |
| S04-1 | ed25519 | Artefak diganti & ditandatangani ulang, SBOM lama dipakai | SBOM_BINDING_MISMATCH | SBOM_BINDING_MISMATCH | 1 | Ya |

## U14 Perbandingan Tanda Tangan

| Profil | Manifest identik | Tanda tangan identik |
|---|---|---|
| rsa-pss-sha256 | True | False |
| ecdsa-p256-sha256 | True | False |
| ed25519 | True | True |

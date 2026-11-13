# LAPORAN TUGAS 3 IF4020 KRIPTOGRAFI
## Penandatanganan dan Verifikasi Software Release (NoraSign)
**Semester 1 Tahun Ajaran 2026/2027**

---

### Disusun Oleh:
1. **Brian A. Hadian** (NIM: 13523048)
2. **Andrew Isra Saputra DB** (NIM: 13523110)

*Program Studi Teknik Informatika*  
*Sekolah Teknik Elektro dan Informatika*  
*Institut Teknologi Bandung*  
*November 2026*

---

## Pernyataan Tidak Melakukan Kecurangan

> *Tugas dan laporan ini disusun sepenuhnya tanpa bantuan kecerdasan buatan (Generative AI), melainkan hasil pemikiran dan analisis mandiri.*

| Tanda Tangan Mahasiswa 1 | Tanda Tangan Mahasiswa 2 |
| :---: | :---: |
| *(Tanda Tangan)* | *(Tanda Tangan)* |
| **Brian A. Hadian (13523048)** | **Andrew Isra Saputra DB (13523110)** |

---

## 1. Pendahuluan

### 1.1 Latar Belakang
Dalam rantai pasok perangkat lunak modern (*software supply chain*), integritas dan keaslian (*provenance*) berkas rilis adalah pilar keamanan kritis. Ancaman seperti modifikasi biner di *mirror*, kompromi *relay* distribusi, atau sisipan *rootkit* pada artefak pembaruan (sebagaimana diilustrasikan dalam narasi kasus ROBO dan Nora) membuktikan bahwa mekanisme pengecekan *checksum* biasa tidak lagi memadai jika berkas *checksum* turut dimanipulasi oleh penyerang.

Oleh karena itu, diperlukan mekanisme tanda tangan digital asimetris yang mengikat identitas penerbit sah dengan deskripsi kanonikal dari rilis perangkat lunak.

### 1.2 Perbandingan dengan Sigstore Cosign
Program **NoraSign** mengadaptasi arsitektur *blob signing* pada kakas industri **Sigstore Cosign**:
- **Sigstore Cosign**: Menyediakan penandatanganan berkas biner/kontainer dengan integrasi infrastruktur PKI transparan (Fulcio, Rekor) atau *key-pair offline*. Cosign membungkus informasi rilis ke dalam struktur *envelope* (seperti in-toto attestation) dan menyimpannya ke *registry* OCI.
- **NoraSign**: Mengadopsi prinsip pemisahan *release manifest* (memuat nama paket, versi, ukuran, dan SHA-256 biner) dan penyimpanan tanda tangan dalam format *bundle* JSON kanonikal (`minisign-bundle/v1`), dengan verifikasi berbasis *local trust store* terisolasi tanpa ketergantungan jaringan runtime (`--network none`).

### 1.3 Gagasan dan Pendekatan Utama
NoraSign dirancang dengan prinsip:
1. **Deterministik & Kanonikal**: Serialisasi manifest JSON bebas spasi luar string, bebas *escape* unicode tak perlu, urutan field deterministik, dan bebas BOM UTF-8 guna menghindari serangan *malleability*.
2. **Strict Verification Pipeline**: Eksekusi 8 tahapan verifikasi yang berhenti (*fail-fast*) pada kesalahan pertama.
3. **Container-Native**: Image biner mandiri berbasis `linux/amd64` yang siap dijalankan pada runner CI/CD dengan isolasi penuh (`--network none`) dan dukungan pengguna non-root (`--user`).

---

## 2. Dasar Teori

### 2.1 RSASSA-PSS (`rsa-pss-sha256`)
RSASSA-PSS (RFC 8017) merupakan skema tanda tangan digital berbasis RSA dengan pembuktian keamanan yang lebih ketat (*provably secure*) dibanding PKCS#1 v1.5. PSS menggunakan salt acak (panjang 32 byte sesuai ukuran SHA-256) dan fungsi *mask generation* MGF1 berbasis SHA-256. Penggunaan modulus 3072 bit memberikan tingkat keamanan setara 128 bit, melampaui standar usang RSA 2048 bit.

### 2.2 ECDSA (`ecdsa-p256-sha256`)
ECDSA (FIPS 186-5) memanfaatkan aritmatika kurva eliptik pada kurva NIST P-256 (secp256r1). Operasi penandatanganan menghasilkan pasangan skalar integer $(r, s)$. Agar portabel dan deterministik, NoraSign mengonversi representasi ASN.1 DER dari pustaka kriptografi menjadi penggabungan biner murni $r \parallel s$ sepanjang tepat 64 byte (masing-masing 32 byte *big-endian*).

### 2.3 Ed25519 (`ed25519`)
Ed25519 (RFC 8032) mengimplementasikan PureEdDSA di atas kurva Edwards Twisted (Curve25519). Keunggulan utama Ed25519 meliputi kekebalan terhadap serangan *side-channel* berbasis waktu, kinerja tinggi, pembangkitan *nonce* internal yang deterministik (bebas kegagalan RNG), dan penandatanganan pesan langsung tanpa *pre-hashing* eksternal.

### 2.4 Fungsi Hash Kriptografis dan Fingerprinting
Fungsi hash SHA-256 digunakan untuk dua tujuan:
1. Integritas artefak rilis biner.
2. Identitas kunci publik (`keyid`), dihitung sebagai:
   $$\text{keyid} = \text{hex\_lower}(\text{SHA-256}(\text{DER\_SPKI}))$$
   Metode ini memastikan bahwa perbedaan format baris PEM (`\r\n` vs `\n`) atau *whitespace* pembungkus tidak mengubah identitas kriptografis kunci.

---

## 3. Perancangan Sistem

### 3.1 Alur Penandatanganan dan Pembentukan Bundle
Alur kerja pembuatan rilis:
1. Signer membaca artefak biner secara langsung tanpa normalisasi byte.
2. Signer menghitung SHA-256 artefak dan panjang byte artefak.
3. Signer menyusun struktur *manifest* kanonikal (`minisign-manifest/v1`).
4. Signer menghasilkan byte manifest kanonikal $M$ (maksimum 16 KiB).
5. Kunci privat PKCS#8 membaca $M$ dan membubuhkan tanda tangan $\sigma$.
6. Manifest $M$ dan tanda tangan $\sigma$ dikodekan ke Base64 standar RFC 4648 dan dikemas ke dalam berkas `bundle.json` (`minisign-bundle/v1`, maksimum 64 KiB).

### 3.2 Alur Verifikasi (8 Tahapan Strict)
1. **INPUT_ERROR (Exit 2)**: Pemeriksaan keberadaan dan keterbacaan berkas input.
2. **FORMAT_ERROR (Exit 1)**: Pemeriksaan kepatuhan struktur JSON, ketiadaan field duplikat, kesesuaian tipe data, batas ukuran berkas, encoding Base64 RFC 4648, dan kesesuaian serialisasi kanonikal manifest byte-for-byte.
3. **UNSUPPORTED_ALGORITHM (Exit 1)**: Nilai string algorithm harus merupakan salah satu dari 3 profil yang didukung.
4. **KEY_NOT_TRUSTED (Exit 1)**: Pencocokan `keyid` pada trust store, kesesuaian profil kunci, dan izin terhadap nama paket.
5. **INVALID_SIGNATURE (Exit 1)**: Verifikasi kriptografis tanda tangan digital atas byte manifest asli $M$.
6. **METADATA_MISMATCH (Exit 1)**: Pencocokan nama paket, versi rilis, dan kesamaan `artifact.name` dengan *basename* berkas masukan.
7. **ARTIFACT_MISMATCH (Exit 1)**: Pencocokan ukuran byte riil berkas artefak dan SHA-256 berkas artefak terhadap nilai pada manifest.
8. **OK (Exit 0)**: Seluruh pemeriksaan lulus.

### 3.3 Threat Model & Mitigasi Keamanan
- **Kebocoran Kunci Privat**: Kunci privat tidak pernah disimpan pada image container, layer build, log runner, maupun bundle JSON. Kunci dipasang (*mount*) sementara dengan mode *read-only* dan dihapus seketika via `trap` shell. Berkas kunci diatur dengan izin berkas restriktif `0600`.
- **Penggunaan Ulang Nonce ECDSA**: Penggunaan nonce acak dari CSPRNG atau RFC 6979 deterministik mencegah kebocoran kunci privat akibat pengulangan nilai $k$.
- **Penggantian Artefak (Tampering)**: Deteksi byte artefak melalui SHA-256 yang terlindungi di dalam manifest bertanda tangan.
- **Rollback Attack**:
  *Analisis*: Rancangan manifest saat ini tidak mencakup nomor urut monotonik global (*trusted counter*) atau *timestamp* yang diikat ke pihak ketiga (misalnya *Transparency Log* Rekor atau *TUF Timestamps*). Akibatnya, penyerang yang memiliki rilis lama yang sah (misalnya versi 1.0.0 dengan kerentanan yang diketahui) dapat menyajikan kembali paket dan bundle lama tersebut.
  *Mitigasi*: Diperlukan *trusted state* tambahan seperti *stateful counter* pada trust store, *minimum version constraint*, atau penandaan waktu bertanda tangan (*Signed Timestamp Authority* / RFC 3161).

---

## 4. Implementasi dan Simulasi

### 4.1 Deskripsi Antarmuka Program (CLI)
Kakas CLI dinamakan **NoraSign** (`norasign`), dibangun dengan bahasa pemrograman Python dan pustaka `cryptography`:
- `norasign keygen --algorithm <profil> --out <prefix> [--force]`
- `norasign sign --file <path> --package <nama> --version <versi> --key <priv.pem> --out <bundle.json>`
- `norasign verify --file <path> --bundle <bundle.json> --trust-store <trust.json> --package <nama> --version <versi> [--json]`
- `norasign trust add / list / remove`
- `norasign sbom generate / verify` (Bonus 3)

### 4.2 Pemetaan Parameter ke Pustaka Kriptografi
| Profil NoraSign | Pustaka `cryptography` API | Mode / Parameter |
| :--- | :--- | :--- |
| `rsa-pss-sha256` | `rsa.RSAPrivateKey.sign` / `verify` | `padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)`, Hash: `hashes.SHA256()` |
| `ecdsa-p256-sha256` | `ec.EllipticCurvePrivateKey.sign` / `verify` | `ec.ECDSA(hashes.SHA256())`, konversi `decode_dss_signature` / `encode_dss_signature` ke biner $r \parallel s$ 64 byte |
| `ed25519` | `ed25519.Ed25519PrivateKey.sign` / `verify` | Input byte manifest $M$ langsung tanpa hash eksternal (PureEdDSA RFC 8032) |

---

## 5. Hasil Pengujian dan Analisis Kinerja

### 5.1 Hasil Pengujian Skenario Minimum (U01 - U14)
Semua skenario pengujian diimplementasikan dan diotomasi menggunakan `pytest`:
- **U01**: Berkas teks, biner 64 KB, dan berkas kosong 0-byte berhasil ditandatangani dan diverifikasi pada ketiga algoritma (`PASS`).
- **U02 & U03**: Modifikasi 1 byte artefak dan penambahan/penghapusan byte terdeteksi sebagai `ARTIFACT_MISMATCH` (`PASS`).
- **U04**: Pengubahan versi pada manifest kanonikal menghasilkan kegagalan tanda tangan `INVALID_SIGNATURE` (`PASS`).
- **U05**: Pembalikan 1 bit pada tanda tangan Base64 menghasilkan `INVALID_SIGNATURE` (`PASS`).
- **U06 & U07**: Trust store kosong atau kunci yang tidak berizin untuk paket menghasilkan `KEY_NOT_TRUSTED` (`PASS`).
- **U08**: Parameter CLI berbeda versi menghasilkan `METADATA_MISMATCH` (`PASS`).
- **U09**: Pengubahan nama berkas artefak menghasilkan `METADATA_MISMATCH` (`PASS`).
- **U10**: Field duplikat, tipe data salah (boolean untuk integer size), Base64 tak beraturan, dan manifest > 16 KiB menghasilkan `FORMAT_ERROR` (`PASS`).
- **U11**: Algorithm profil tak dikenal menghasilkan `UNSUPPORTED_ALGORITHM` (`PASS`).
- **U12**: Kunci valid yang belum dimasukkan ke trust store menghasilkan `KEY_NOT_TRUSTED` (`PASS`).
- **U13**: Modifikasi whitespace pada bundle JSON tetap berhasil diproses (`PASS`).
- **U14**: Dua penandatanganan berurutan membuktikan RSA-PSS menghasilkan tanda tangan berbeda (karena salt acak 32 byte), sedangkan Ed25519 menghasilkan tanda tangan identik (deterministik). Keduanya valid saat diverifikasi (`PASS`).

### 5.2 Pengujian Interoperabilitas dengan OpenSSL
Tanda tangan yang dihasilkan NoraSign berhasil diverifikasi menggunakan OpenSSL 3.0 CLI standar:
- RSA-PSS: diverifikasi dengan `openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -verify` (`Verified OK`).
- ECDSA: setelah dikemas kembali ke DER via ASN.1, diverifikasi dengan `openssl dgst -sha256 -verify` (`Verified OK`).
- Ed25519: diverifikasi dengan `openssl pkeyutl -verify -rawin` (`Signature Verified Successfully`).

### 5.3 Hasil Benchmark Kinerja (Tabel 2.12)
Pengukuran dilakukan pada mesin Linux x86_64 dengan 5 warmup dan 30 perulangan menggunakan timer monotonik `time.perf_counter_ns()`:

#### Pembangkitan Kunci (Key Generation)
- `rsa-pss-sha256`: Median 425.862 ms, P95: 1025.966 ms.
- `ecdsa-p256-sha256`: Median 0.042 ms, P95: 0.161 ms.
- `ed25519`: Median 0.038 ms, P95: 0.161 ms.

#### Operasi Kriptografi Murni atas Manifest
- `rsa-pss-sha256`: Sign 1.315 ms, Verify 0.045 ms.
- `ecdsa-p256-sha256`: Sign 0.032 ms, Verify 0.062 ms.
- `ed25519`: Sign 0.032 ms, Verify 0.075 ms.

#### Ukuran Komponen (Bytes)
| Algoritma | Private Key DER | Public Key SPKI DER | Raw Signature | Bundle JSON |
| :--- | :---: | :---: | :---: | :---: |
| `rsa-pss-sha256` | 1794 B | 422 B | 384 B | 794 B |
| `ecdsa-p256-sha256` | 138 B | 91 B | 64 B | 370 B |
| `ed25519` | 48 B | 44 B | 64 B | 370 B |

---

## 6. Kesimpulan dan Saran Pengembangan

### 6.1 Kesimpulan
NoraSign berhasil mengimplementasikan spesifikasi penandatanganan dan verifikasi rilis perangkat lunak sesuai standar IF4020. Penggunaan Ed25519 dan ECDSA P-256 memberikan efisiensi komputasi dan ukuran bundle yang jauh lebih ringkas dibanding RSA 3072, sementara RSA-PSS memberikan verifikasi tercepat karena eksponen kecil $e=65537$.

### 6.2 Saran Pengembangan
1. Integrasi arsitektur Sigstore Rekor (*transparency log*) untuk perlindungan terhadap *rollback attacks*.
2. Dukungan verifikasi *in-toto supply chain attestation* berlapis.

---

## 7. Lampiran

### 7.1 Pembagian Tugas Anggota Kelompok
| Anggota Kelompok | NIM | Komponen yang Dikerjakan |
| :--- | :---: | :--- |
| **Brian A. Hadian** | 13523048 | Arsitektur Sistem, Komponen 1 (Crypto Engine: RSA-PSS, ECDSA, Ed25519), Komponen 2 (Manifest & Bundle Engine), Komponen 6 (CLI & Dockerization), Skrip Benchmark & Interoperabilitas OpenSSL, CI/CD Workflow (`.github/workflows/ci.yml`), Dokumentasi API (Bonus 2), Penyusunan Draf Laporan. |
| **Andrew Isra Saputra DB** | 13523110 | Komponen 3 (Trust Store Management: atomic update, format minisign-trust/v1), Komponen 4 (8-Step Verification Pipeline & exit code mapping), Komponen 5 (Bonus 3 Signed SBOM generate & verify), Eksekusi U01-U14 & C01-C05, Video Demo (Bonus 1). |

### 7.2 Tautan Repositori & Dokumentasi
- Repositori: `https://github.com/BrianHadianSTEI23/tugas3-IF4020-13523048-13523110`
- Image Registry: `ghcr.io/brianhadianstei23/norasign:1.0.0`

# 📘 Bitcoin wallet.dat Password Checker v2.0

> **Materi Edukasi** · Bahasa Indonesia  
> Untuk: mahasiswa kriptografi, tim forensik digital, developer blockchain

---

## 📋 Daftar Isi

1. [Apa Itu Alat Ini?](#1-apa-itu-alat-ini)
2. [File yang Tersedia](#2-file-yang-tersedia)
3. [Changelog — Riwayat Versi](#3-changelog--riwayat-versi)
4. [Latar Belakang: Bagaimana Bitcoin Core Menyimpan Password?](#4-latar-belakang-bagaimana-bitcoin-core-menyimpan-password)
5. [Format Hash HashCat ($bitcoin$)](#5-format-hash-hashcat-bitcoin)
6. [Alur Verifikasi — Langkah demi Langkah](#6-alur-verifikasi--langkah-demi-langkah)
7. [KDF: SHA-512 Iteratif (Inti dari Segalanya)](#7-kdf-sha-512-iteratif-inti-dari-segalanya)
8. [Enkripsi AES-256-CBC](#8-enkripsi-aes-256-cbc)
9. [Validasi Padding PKCS7](#9-validasi-padding-pkcs7)
10. [Bug yang Ditemukan & Diperbaiki (Semua Versi)](#10-bug-yang-ditemukan--diperbaiki-semua-versi)
11. [Cara Mengekstrak Hash dari wallet.dat](#11-cara-mengekstrak-hash-dari-walletdat)
12. [Penjelasan Kode — Fungsi per Fungsi](#12-penjelasan-kode--fungsi-per-fungsi)
13. [Perbandingan: SHA-512 Iteratif vs PBKDF2 vs scrypt](#13-perbandingan-sha-512-iteratif-vs-pbkdf2-vs-scrypt)
14. [Keamanan & Etika Penggunaan](#14-keamanan--etika-penggunaan)
15. [Referensi & Bacaan Lanjutan](#15-referensi--bacaan-lanjutan)

---

## 1. Apa Itu Alat Ini?

Alat ini adalah **verifikator password** untuk file `wallet.dat` yang digunakan oleh Bitcoin Core dan Litecoin Core. Alat ini berjalan sepenuhnya di **browser** (sisi klien) — tidak ada data yang pernah dikirim ke server mana pun.

**Fungsi inti:**
Menerima hash dalam format HashCat (`$bitcoin$...`) dan sebuah password, lalu memverifikasi apakah password tersebut benar atau tidak — tanpa perlu akses ke file `wallet.dat` asli.

**Siapa yang menggunakannya?**

* Pemilik wallet yang lupa password dan ingin memverifikasi kandidat password
* Tim forensik digital
* Peneliti keamanan yang mempelajari kriptografi wallet Bitcoin
* Mahasiswa yang ingin memahami cara kerja enkripsi wallet

---

## 2. File yang Tersedia

| File | Bahasa | Keterangan |
| --- | --- | --- |
| `bitcoin-batch-checker-id.html` | 🇮🇩 Indonesia | Batch checker v2 — verifikasi 100+ hash dengan wordlist (UI Indonesia) |
| `bitcoin-batch-checker-en.html` | 🇬🇧 Inggris | Batch checker v2 — versi bahasa Inggris |
| `README-ID.md` | 🇮🇩 Indonesia | Dokumentasi ini |
| `README.md` | 🇬🇧 Inggris | Dokumentasi bahasa Inggris |

> **Catatan:** Kedua file HTML menyertakan tab Single Check (satu hash + satu password) dan tab Batch Check (banyak hash + wordlist) dalam satu file yang sama.

---

## 3. Changelog — Riwayat Versi

### 🔖 v1.0 — Single Hash Checker

**Status:** Stabil — Bug telah diperbaiki

#### Fitur di v1.0

* Input satu hash (`$bitcoin$` atau `$litecoin$`) + satu password
* Tombol tampilkan/sembunyikan password
* Tampilan info debug (key, IV, ciphertext, hasil dekripsi, padding)
* Validasi format hash dengan pesan error yang deskriptif
* 100% sisi klien, tidak ada request ke server

#### Bug yang Ditemukan & Diperbaiki di v1.0

**🐛 Bug #1 — Fungsi helper tidak diimplementasikan** *(Tingkat keparahan: Kritis)*

```
Kondisi awal:
  function hexToBytes(hex) { /* ... */ }       // kosong!
  function bytesToHex(bytes) { /* ... */ }     // kosong!
  function uint8ToWordArray(u8) { /* ... */ }  // kosong!
  function wordArrayToUint8(wa) { /* ... */ }  // kosong!

Dampak: Alat langsung crash saat pertama kali dijalankan.
Perbaikan: Implementasi penuh semua fungsi konversi.
```

**🐛 Bug #2 — mkHexLen salah diinterpretasi (dikalikan 2)** *(Tingkat keparahan: Kritis)*

```
Kondisi awal:
  if (masterKeyHex.length !== mkLen * 2)  // ← perkalian *2 ini SALAH

Contoh: hash $bitcoin$64$... → mkLen = 64
  Kode lama mengharapkan: 64 * 2 = 128 karakter hex
  Kenyataan: mkHex hanya 64 karakter → selalu ERROR!

Penjelasan: mkHexLen adalah panjang STRING HEX, bukan jumlah byte.
  64 karakter hex = 32 byte (bukan 64 byte)

Perbaikan: if (masterKeyHex.length !== mkHexLen)  // tanpa *2
```

**🐛 Bug #3 — KDF yang digunakan salah: scrypt bukan SHA-512** *(Tingkat keparahan: Kritis)*

```
Kondisi awal:
  const derivedBytes = await scrypt.scrypt(
      new TextEncoder().encode(password),
      saltBytes, N, r, p, dkLen          // ← scrypt! SALAH
  );

Bitcoin Core TIDAK menggunakan scrypt untuk enkripsi wallet.dat.
Bitcoin Core menggunakan SHA-512 iteratif (crypter.cpp).

Dampak: Alat selalu mengembalikan "Password Salah" meskipun
        password 100% benar.

Perbaikan: Implementasikan KDF SHA-512 iteratif yang benar:
  hash = SHA512(password + salt)   ← putaran 1
  hash = SHA512(hash)              ← putaran 2..N
  key = hash[0..31], iv = hash[32..47]
```

**🐛 Bug #4 — Validasi berbasis XOR tidak memiliki dasar teknis** *(Tingkat keparahan: Tinggi)*

```
Kondisi awal:
  // XOR hasil dekripsi dengan wallet IV
  xorResult[i] = decryptedBytes[i] ^ masterKeyBytes[i];
  // Cek apakah semua byte = 0x10
  isValid = xorResult.every(b => b === 0x10);

Logika ini sama sekali tidak memiliki dasar kriptografi.

Perbaikan: Gunakan validasi PKCS7 standar (lihat Bug #5 untuk
     penyempurnaan lebih lanjut di v1.1).
```

---

### 🔖 v1.1 — Single Hash Checker (Hotfix)

**Status:** Stabil — Hotfix setelah pengujian nyata

#### Latar Belakang v1.1

Setelah v1.0 dirilis, pengujian nyata dengan hash dari wallet bersaldo nol menemukan **false positive** — alat melaporkan password benar padahal Bitcoin Core menolaknya.

Hash uji: `$bitcoin$64$ff4eb1d0...$16$6b8207637fc796a0$37698$2$00$2$00`  
Password uji: `"2315"` → v1.0 mengatakan **BENAR** ❌ (seharusnya **SALAH**)

**🐛 Bug #5 — False Positive PKCS7: Padding `0x01` Selalu Lolos** *(Tingkat keparahan: Tinggi)*

```
Kondisi di v1.0 (setelah memperbaiki Bug #4):
  const last = decryptedBytes[decryptedBytes.length - 1];
  let isValid = (last >= 1 && last <= 16);  // ← terlalu longgar!

Masalah:
  Password salah → dekripsi menghasilkan data acak → byte terakhir = 0x01
  Validasi: 0x01 >= 1 && 0x01 <= 16 → TRUE → false positive!

  Probabilitas false positive: ~6,25% (1 dari 16 kemungkinan)
  Artinya: ~1 dari 16 password salah akan dilaporkan sebagai BENAR.

Akar masalah:
  Master key Bitcoin Core SELALU 32 byte (AES-256).
  PKCS7 pada 32 byte data → padding = satu blok penuh = 16 × 0x10
  Hashcat mengambil 2 blok terakhir (32 byte) → blok terakhir = semua 0x10

Perbaikan — Validasi ketat khusus Bitcoin:
  let isValid = (last === 0x10);  // harus tepat 0x10
  if (isValid) {
      for (let i = decBytes.length - 16; i < decBytes.length; i++) {
          if (decBytes[i] !== 0x10) { isValid = false; break; }
      }
  }

  Probabilitas false positive setelah perbaikan: ~1/(256^16) ≈ nol
```

---

### 🔖 v2.0 — Batch Checker (Rilis Mayor)

**File:** `bitcoin-batch-checker-id.html` / `bitcoin-batch-checker-en.html`  
**Status:** Stabil — Saat ini

#### Fitur Baru di v2.0

**⚡ Tab Batch Checker**

* Input daftar hash (100+ sekaligus), satu per baris
* Input wordlist password, satu per baris
* Upload file `.txt` wordlist langsung dari browser
* Progress bar real-time dengan statistik lengkap:
  + Jumlah ditemukan / diperiksa / tersisa
  + Kecepatan (hash/menit)
  + Estimasi waktu selesai (ETA)
* Mesin konkurensi: proses 1 / 2 / 4 kombinasi secara paralel
* Tombol **Pause** — jeda tanpa kehilangan progres
* Tombol **Stop** — hentikan kapan saja
* Mode: "berhenti saat ditemukan" atau "coba semua password"
* Log langsung dengan timestamp untuk setiap aktivitas
* Filter tabel hasil: Semua / Ditemukan / Gagal / Error
* Ekspor hasil ke **CSV** (semua hasil atau hanya yang ditemukan)
* Salin password yang ditemukan ke clipboard
* Kartu ringkasan: total ditemukan, gagal, total hash, waktu berlalu

**🔍 Tab Single Check**

* Verifikasi satu hash + satu password
* Fungsional identik dengan v1.1
* Semua perbaikan bug disertakan

**📖 Tab Panduan**

* Dokumentasi format hash inline
* Penjelasan algoritma verifikasi
* Tips batch checking

**🌐 Tersedia dalam dua bahasa**

* `bitcoin-batch-checker-id.html` — Indonesia
* `bitcoin-batch-checker-en.html` — Inggris

#### Peningkatan Teknis di v2.0

| Aspek | v1.x | v2.0 |
| --- | --- | --- |
| Hash per sesi | 1 | 1 — 1000+ |
| Password per sesi | 1 | 1 — tak terbatas |
| Konkurensi | — | 1 / 2 / 4 paralel |
| Pelacakan progres | — | Real-time dengan ETA |
| Ekspor hasil | — | CSV + clipboard |
| Pause / Stop | — | ✓ |
| Log langsung | — | ✓ (buffer 500 baris) |
| Upload wordlist | — | ✓ (.txt) |
| Bahasa | Indonesia | Indonesia + Inggris |
| Mesin kripto | SHA-512 + AES + PKCS7 ketat | Diwarisi — tidak berubah |

#### Mesin Kripto Tidak Berubah

> Semua logika kriptografi (KDF SHA-512 iteratif, AES-256-CBC, validasi padding ketat `0x10×16`) identik antara v1.1 dan v2.0. Tidak ada bug kripto baru yang diperkenalkan atau ditemukan.

---

## 4. Latar Belakang: Bagaimana Bitcoin Core Menyimpan Password?

Saat kamu mengenkripsi wallet di Bitcoin Core, program tidak langsung mengenkripsi private key dengan passwordmu. Ada beberapa lapisan:

```
┌───────────────────────────────────────────────────────────┐
│           ARSITEKTUR ENKRIPSI WALLET                      │
│                                                           │
│  PASSWORD (teks biasa dari pengguna)                      │
│       │                                                   │
│       ▼                                                   │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  KDF: SHA-512 Iteratif + Salt (N iterasi)           │  │
│  │  → Menghasilkan: Key (32 byte) + IV (16 byte)       │  │
│  └─────────────────────────────────────────────────────┘  │
│       │                                                   │
│       ▼                                                   │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  Dekripsi AES-256-CBC pada Encrypted Master Key     │  │
│  └─────────────────────────────────────────────────────┘  │
│       │                                                   │
│       ▼                                                   │
│  Master Key (teks biasa) → digunakan untuk mengenkripsi   │
│  semua Private Key di dalam wallet                        │
└───────────────────────────────────────────────────────────┘
```

**Konsep Kunci:**

* **Master Key** — Kunci rahasia utama untuk mengenkripsi semua private key. Master key ini sendiri dienkripsi menggunakan password pengguna.
* **Salt** — Data acak yang ditambahkan sebelum hashing. Mencegah serangan rainbow table.
* **Iterasi (N)** — Berapa kali SHA-512 diulang. N lebih tinggi = brute-force lebih lambat.
* **IV (Initialization Vector)** — Nilai awal untuk mode CBC. Diturunkan dari KDF, tidak disimpan secara terpisah.

---

## 5. Format Hash HashCat ($bitcoin$)

Hash dihasilkan oleh `bitcoin2john.py` (dari paket John the Ripper) saat membaca `wallet.dat`.

### Struktur Format

```
$bitcoin$<mkHexLen>$<mkHex>$<saltHexLen>$<saltHex>$<iterations>$<f1>$<f2>$<f3>$<f4>
```

### Tabel Referensi Field

| Posisi | Nama Field | Tipe | Keterangan |
| --- | --- | --- | --- |
| [0] | `mkHexLen` | integer | **Panjang STRING HEX** untuk masterKey — bukan jumlah byte! |
| [1] | `mkHex` | hex | Encrypted Master Key dalam hex |
| [2] | `saltHexLen` | integer | **Panjang STRING HEX** untuk salt — bukan jumlah byte! |
| [3] | `saltHex` | hex | Salt dalam hex |
| [4] | `iterations` | integer | Jumlah iterasi SHA-512 |
| [5..8] | (ekstra) | — | Field tambahan, tidak digunakan dalam verifikasi |

### Contoh Hash Nyata

```
$bitcoin$64$286ab85b3f33d80f954b8fdf272bf9884884499e783699e8d4c7c266c3fd6023$16$69e2890df94ce226$244252$2$00$2$00
$bitcoin$64$9618854225c49afded96d7f2562b078f685867e583865f0c85f794379849254b$16$6bb5d8031eaa5933$247325$2$00$2$00
```

Penjelasan per bagian:

```
Prefix      : $bitcoin$
mkHexLen    : 64   → mkHex memiliki panjang 64 karakter hex = 32 byte
mkHex       : 286ab85b3f33d80f954b8fdf272bf9884884499e783699e8d4c7c266c3fd6023
saltHexLen  : 16   → saltHex memiliki panjang 16 karakter hex = 8 byte
saltHex     : 69e2890df94ce226
iterations  : 244252
```

### ⚠️ Kesalahan Umum — mkHexLen BUKAN Jumlah Byte!

```
SALAH ❌:  expected_length = mkHexLen * 2
           → 64 * 2 = 128 karakter hex (tidak benar!)

BENAR ✅:  expected_length = mkHexLen
           → 64 karakter hex (benar!)
```

`mkHexLen` adalah jumlah **karakter hex**, bukan byte. Karena 1 byte = 2 karakter hex, `mkHexLen=64` berarti 64 karakter hex = 32 byte.

---

## 6. Alur Verifikasi — Langkah demi Langkah

```
INPUT: hash ($bitcoin$...) + password (teks)
           │
           ▼
┌──────────────────────────┐
│  LANGKAH 1: Parse Hash   │
│  Ekstrak mkHex, saltHex, │
│  iterations              │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  LANGKAH 2: KDF          │
│  SHA-512 Iteratif        │
│  Input: password + salt  │
│  Ulangi N kali           │
│  Output: 64 byte         │
│  key = byte[0..31]       │
│  iv  = byte[32..47]      │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  LANGKAH 3: Dekripsi AES │
│  AES-256-CBC             │
│  Key = 32 byte dari KDF  │
│  IV  = 16 byte dari KDF  │
│  Data = mkHex[0..31]     │
│  Output: 32 byte         │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  LANGKAH 4: Cek Padding  │
│  16 byte terakhir        │
│  harus semua = 0x10?     │
└──────────┬───────────────┘
           │
     ┌─────┴──────┐
     ▼            ▼
  YA ✅         TIDAK ❌
"Password    "Password
  Benar!"      Salah!"
```

---

## 7. KDF: SHA-512 Iteratif (Inti dari Segalanya)

KDF = **Key Derivation Function** — fungsi untuk menurunkan kunci kriptografi dari password teks biasa.

### Algoritma Bitcoin Core (crypter.cpp)

```
PUTARAN 1:
  data = byte(password) + byte(salt)
  hash = SHA-512(data)              ← 64 byte

PUTARAN 2 hingga N:
  hash = SHA-512(hash)              ← hanya hash sebelumnya!

OUTPUT AKHIR (64 byte):
  key = hash[0..31]                 ← 32 byte untuk AES-256
  iv  = hash[32..47]                ← 16 byte untuk AES CBC
```

### Implementasi JavaScript

```javascript
async function deriveKeyBitcoinSHA512(password, saltBytes, iterations) {
    const passBytes = new TextEncoder().encode(password);

    // Gabungkan password + salt
    const combined = new Uint8Array(passBytes.length + saltBytes.length);
    combined.set(passBytes, 0);
    combined.set(saltBytes, passBytes.length);

    // Putaran 1: SHA-512(password + salt)
    let hashBuf = await crypto.subtle.digest('SHA-512', combined);

    // Putaran 2..N: SHA-512(hash sebelumnya saja)
    for (let i = 1; i < iterations; i++) {
        hashBuf = await crypto.subtle.digest('SHA-512', hashBuf);
    }

    return new Uint8Array(hashBuf); // 64 byte
}
```

### Visualisasi Iterasi

```
Iterasi   Input                             Output
───────── ───────────────────────────────── ──────────────────
1         SHA-512(password + salt)       →  hash₁  (64 byte)
2         SHA-512(hash₁)                 →  hash₂  (64 byte)
3         SHA-512(hash₂)                 →  hash₃  (64 byte)
...       ...                               ...
N         SHA-512(hash_{N-1})            →  hashₙ  (64 byte)

key = hashₙ[0..31]   (32 byte)
iv  = hashₙ[32..47]  (16 byte)
```

### Mengapa Iterasi Diperlukan?

Tanpa iterasi, penyerang dapat mencoba jutaan password per detik di GPU. Dengan `iterations = 35714`, setiap percobaan membutuhkan 35.714 komputasi SHA-512 — membuat brute-force jauh lebih lambat.

> **Analogi:** Seperti mengunci pintu dengan 35.714 gembok yang masing-masing harus dibuka satu per satu, secara berurutan.

---

## 8. Enkripsi AES-256-CBC

### AES (Advanced Encryption Standard)

AES adalah algoritma enkripsi simetris yang menjadi standar industri. Simetris berarti kunci yang sama digunakan untuk enkripsi maupun dekripsi.

* **AES-256**: Kunci 256-bit (32 byte)
* **CBC (Cipher Block Chaining)**: Mode operasi yang merantai blok data

### Cara Kerja CBC

```
ENKRIPSI:
  P₁  XOR  IV  → AES(key) → C₁
  P₂  XOR  C₁  → AES(key) → C₂
  P₃  XOR  C₂  → AES(key) → C₃

DEKRIPSI:
  AES_dec(key, C₁)  XOR  IV  → P₁
  AES_dec(key, C₂)  XOR  C₁  → P₂
  AES_dec(key, C₃)  XOR  C₂  → P₃
```

### Mengapa IV Penting?

IV memastikan bahwa plaintext yang sama menghasilkan ciphertext yang berbeda setiap kali dienkripsi (selama IV berbeda). Di Bitcoin Core, IV tidak disimpan secara terpisah — IV dibuat ulang dari KDF setiap kali diperlukan.

---

## 9. Validasi Padding PKCS7

### Mengapa Padding Diperlukan?

AES-CBC bekerja pada blok 16 byte. Jika data bukan kelipatan 16, padding ditambahkan.

### Skema PKCS7

```
Data kurang N byte dari kelipatan 16 → tambahkan N byte bernilai N

Contoh (kurang 3 byte):
  [data asli...]  03 03 03

Kasus Bitcoin (data 32 byte = kelipatan 16 → padding blok penuh):
  [32 byte data]  10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
                  ↑ 0x10 = 16 desimal, diulang 16 kali
```

### Validasi Ketat Khusus Bitcoin

```javascript
// ❌ VALIDASI LONGGAR — rentan false positive (~6,25%):
const last = decryptedBytes[decryptedBytes.length - 1];
let isValid = (last >= 1 && last <= 16);  // 0x01 selalu lolos!

// ✅ VALIDASI KETAT — khusus Bitcoin (false positive ~0):
let isValid = (last === 0x10);  // harus tepat 0x10
if (isValid) {
    for (let i = decryptedBytes.length - 16; i < decryptedBytes.length; i++) {
        if (decryptedBytes[i] !== 0x10) { isValid = false; break; }
    }
}
```

**Mengapa harus tepat `0x10`?** Karena master key Bitcoin selalu 32 byte (AES-256), dan PKCS7 pada 32 byte data menghasilkan tepat satu blok penuh padding = 16 × `0x10`.

---

## 10. Bug yang Ditemukan & Diperbaiki (Semua Versi)

Ringkasan semua bug dari v1.0 hingga v1.1:

| # | Bug | Keparahan | Ditemukan di | Diperbaiki di | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Fungsi helper tidak diimplementasikan | Kritis | v1.0 awal | v1.0 | ✅ Diperbaiki |
| 2 | `mkHexLen` dikalikan 2 — interpretasi salah | Kritis | v1.0 awal | v1.0 | ✅ Diperbaiki |
| 3 | KDF salah: scrypt digunakan alih-alih SHA-512 | Kritis | v1.0 awal | v1.0 | ✅ Diperbaiki |
| 4 | Validasi berbasis XOR tidak memiliki dasar teknis | Tinggi | v1.0 awal | v1.0 | ✅ Diperbaiki |
| 5 | False positive PKCS7: padding `0x01` selalu lolos | Tinggi | v1.0 (pengujian nyata) | v1.1 | ✅ Diperbaiki |

Detail lengkap setiap bug ada di [Changelog](#3-changelog--riwayat-versi).

---

## 11. Cara Mengekstrak Hash dari wallet.dat

### Menggunakan bitcoin2john.py

```bash
# Install dependensi
pip install bsddb3

# Ekstrak hash
python bitcoin2john.py /path/ke/wallet.dat
```

Output:

```
wallet.dat:$bitcoin$64$xxxxx$16$xxxxx$25000$2$00$2$00
```

Bagian setelah `:` adalah hash yang ditempelkan ke alat ini.

### Menggunakan hashcat (Referensi Edukasi)

```bash
# Mode -m 11300 = Bitcoin/Litecoin wallet.dat
hashcat -m 11300 hash.txt wordlist.txt

# Dengan rules
hashcat -m 11300 hash.txt wordlist.txt -r rules/best64.rule
```

> **Penting:** Gunakan hanya pada wallet milikmu sendiri atau dengan izin tertulis resmi.

---

## 12. Penjelasan Kode — Fungsi per Fungsi

### `hexToBytes(hex)`

```javascript
function hexToBytes(hex) {
    // Input:  "dff2b89e"
    // Output: Uint8Array([0xdf, 0xf2, 0xb8, 0x9e])
    hex = hex.replace(/\s+/g, '');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++)
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
}
```

### `uint8ToWordArray(u8)`

CryptoJS menggunakan format internal `WordArray` (array integer 32-bit, big-endian). Fungsi ini mengonversi `Uint8Array` standar ke format tersebut.

```javascript
function uint8ToWordArray(u8) {
    const words = [];
    for (let i = 0; i < u8.length; i += 4)
        words.push(
            ((u8[i]   || 0) << 24) |  // byte 1 → bit 31-24
            ((u8[i+1] || 0) << 16) |  // byte 2 → bit 23-16
            ((u8[i+2] || 0) <<  8) |  // byte 3 → bit 15-8
            ((u8[i+3] || 0))          // byte 4 → bit 7-0
        );
    return CryptoJS.lib.WordArray.create(words, u8.length);
}
```

### `parseBitcoinHash(hashStr)`

```javascript
function parseBitcoinHash(hashStr) {
    // Input: "$bitcoin$64$286ab85b...23$16$69e2890df94ce226$244252$2$00$2$00"
    const parts = hashStr.slice("$bitcoin$".length).split('$');
    // parts: ["64", "617c4b22...96", "16", "69e2890df94ce226", "244252", ...]

    const mkHexLen   = parseInt(parts[0]);  // 64
    const masterKey  = parts[1];            // string hex 64 karakter
    const saltHexLen = parseInt(parts[2]);  // 16
    const saltHex    = parts[3];            // string hex 16 karakter
    const iterations = parseInt(parts[4]);  // 244252

    // KUNCI: validasi langsung, tanpa *2
    if (masterKey.length !== mkHexLen) throw new Error("...");
    return { masterKeyHex: masterKey, saltHex, iterations };
}
```

### `deriveKeyBitcoinSHA512(password, saltBytes, iterations)`

```javascript
async function deriveKeyBitcoinSHA512(password, saltBytes, iterations) {
    const passBytes = new TextEncoder().encode(password);

    // Gabungkan password + salt
    const combined = new Uint8Array(passBytes.length + saltBytes.length);
    combined.set(passBytes, 0);
    combined.set(saltBytes, passBytes.length);

    // Putaran 1: SHA-512(password + salt)
    let hashBuf = await crypto.subtle.digest('SHA-512', combined);

    // Putaran 2..N: SHA-512(hash saja)
    for (let i = 1; i < iterations; i++)
        hashBuf = await crypto.subtle.digest('SHA-512', hashBuf);

    // key = [0..31], iv = [32..47]
    return new Uint8Array(hashBuf);
}
```

---

## 13. Perbandingan: SHA-512 Iteratif vs PBKDF2 vs scrypt

| Kriteria | SHA-512 Iteratif | PBKDF2-SHA512 | scrypt |
| --- | --- | --- | --- |
| **Diperkenalkan** | ~2009 | 2000 (RFC 2898) | 2009 |
| **Tahan GPU?** | Rendah | Rendah-Menengah | Tinggi (memory-hard) |
| **Tahan ASIC?** | Tidak | Tidak | Ya |
| **Kompleksitas** | Sangat sederhana | Menengah | Kompleks |
| **Parameter** | hanya iterations | iter, keyLen | N, r, p, keyLen |
| **Digunakan Bitcoin** | Enkripsi wallet.dat | Seed BIP39 | Mining Litecoin |
| **Ukuran output** | Tetap 64 byte | Variabel | Variabel |
| **Standar modern?** | Tidak (legacy) | Diterima | Sangat direkomendasikan |

**Kesimpulan:** KDF SHA-512 iteratif yang digunakan Bitcoin Core adalah pilihan desain warisan dari 2009. Untuk sistem baru, gunakan PBKDF2 atau **Argon2** (pemenang Password Hashing Competition 2015).

---

## 14. Keamanan & Etika Penggunaan

### ✅ Penggunaan yang Diizinkan

* Memverifikasi password wallet milikmu sendiri
* Penelitian keamanan dengan izin tertulis dari pemilik wallet
* Edukasi dan pembelajaran kriptografi
* Forensik digital di bawah kewenangan hukum resmi

### ❌ Penggunaan yang Dilarang

* Mengakses wallet orang lain tanpa izin
* Brute-force wallet yang bukan milikmu
* Segala bentuk pencurian aset digital

### 🔒 Privasi Alat Ini

Alat ini **100% sisi klien**. Semua komputasi terjadi di browsermu. Tidak ada data (hash, password, hasil) yang pernah dikirim ke server mana pun. Kamu dapat memverifikasi ini dengan memantau tab Network di DevTools browsermu.

---

## 15. Referensi & Bacaan Lanjutan

| Sumber | Keterangan |
| --- | --- |
| `src/wallet/crypter.cpp` (Bitcoin Core) | Implementasi KDF dan enkripsi wallet asli |
| RFC 2898 | Spesifikasi PBKDF2 |
| FIPS 197 | Spesifikasi AES |
| RFC 2315 | Spesifikasi padding PKCS7 |
| `bitcoin2john.py` (John the Ripper) | Alat untuk mengekstrak hash dari wallet.dat |
| Hashcat mode 11300 | Dokumentasi format hash wallet Bitcoin |

### Topik Lanjutan untuk Dijelajahi

* **BIP32/BIP39** — Hierarchical Deterministic Wallets dan frasa seed mnemonik
* **BIP38** — Enkripsi private key dengan scrypt (berbeda dari wallet.dat!)
* **Argon2** — KDF modern, pemenang Password Hashing Competition 2015
* **HSM (Hardware Security Module)** — Penyimpanan kunci kriptografi tingkat enterprise

---

## Penutup

Alat dan dokumentasi ini dibuat untuk **tujuan edukasi** — untuk membantu mahasiswa dan profesional memahami cara kerja sistem kriptografi nyata di dalam wallet Bitcoin. Memahami bug dalam implementasi yang salah mengajarkan kita bahwa kriptografi yang "hampir benar" sama berbahayanya dengan tidak ada kriptografi sama sekali.

Selamat belajar! 🚀

---

## Donasi

### Jika alat ini bermanfaat untuk edukasi dan pembelajaran Anda, donasi sangat diapresiasi:

* **Bitcoin (BTC)** — bc1qn6t8hy8memjfzp4y3sh6fvadjdtqj64vfvlx58
* **Ethereum (ETH)** — 0x512936ca43829C8f71017aE47460820Fe703CAea
* **Solana (SOL)** — 6ZZrRmeGWMZSmBnQFWXG2UJauqbEgZnwb4Ly9vLYr7mi
* **PayPal:** — syabiz@yandex.com

Donasi akan digunakan untuk pengembangan fitur baru, pemeliharaan server, dan dokumentasi.

---

## Kontak

* **Web Script:** https://syabiz.github.io/pages/Bitcoin-Wallet-Checker/
* **GitHub Issues:** https://github.com/syabiz/Bitcoin-Hash-Wallet-Checker-HTML/issues
* **Email:** syabiz@yandex.com
* **Twitter:** @syabiz

---

Terima kasih telah menggunakan Bitcoin Wallet Checker Tool! 🚀  
*Dibuat dengan ❤️ untuk edukasi dan pembelajaran Bitcoin*

*Terakhir diperbarui: Februari 2026*

---

*Dibuat untuk tujuan edukasi. Gunakan dengan bertanggung jawab.*

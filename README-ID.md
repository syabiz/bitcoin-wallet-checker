# 📘 Bitcoin wallet.dat Password Checker v2.0

> **Materi Edukasi Internal** · Bahasa Indonesia  
> Cocok untuk: pelajar kriptografi, tim forensik digital, developer blockchain

---

## 📋 Daftar Isi

1. [Apa Itu Tool Ini?](#1-apa-itu-tool-ini)
2. [File yang Tersedia](#2-file-yang-tersedia)
3. [Changelog — Riwayat Versi](#3-changelog--riwayat-versi)
4. [Latar Belakang: Bagaimana Bitcoin Core Menyimpan Password?](#4-latar-belakang-bagaimana-bitcoin-core-menyimpan-password)
5. [Format Hash HashCat ($bitcoin$)](#5-format-hash-hashcat-bitcoin)
6. [Alur Kerja Verifikasi — Langkah demi Langkah](#6-alur-kerja-verifikasi--langkah-demi-langkah)
7. [KDF: SHA-512 Iteratif (Inti dari Segalanya)](#7-kdf-sha-512-iteratif-inti-dari-segalanya)
8. [Enkripsi AES-256-CBC](#8-enkripsi-aes-256-cbc)
9. [Validasi PKCS7 Padding](#9-validasi-pkcs7-padding)
10. [Bug yang Ditemukan & Diperbaiki (Semua Versi)](#10-bug-yang-ditemukan--diperbaiki-semua-versi)
11. [Cara Mendapatkan Hash dari wallet.dat](#11-cara-mendapatkan-hash-dari-walletdat)
12. [Penjelasan Kode per Fungsi](#12-penjelasan-kode-per-fungsi)
13. [Perbandingan: SHA-512 Iteratif vs PBKDF2 vs scrypt](#13-perbandingan-sha-512-iteratif-vs-pbkdf2-vs-scrypt)
14. [Keamanan & Etika Penggunaan](#14-keamanan--etika-penggunaan)
15. [Referensi & Bacaan Lanjutan](#15-referensi--bacaan-lanjutan)

---

## 1. Apa Itu Tool Ini?

Tool ini adalah **verifikator password** untuk file `wallet.dat` milik Bitcoin Core dan Litecoin Core. Bekerja sepenuhnya di **browser** (client-side) — tidak ada data yang dikirim ke server manapun.

**Fungsi utama:**
Menerima hash dalam format HashCat (`$bitcoin$...`) dan sebuah password, lalu memverifikasi apakah password tersebut benar atau salah — tanpa perlu membuka file `wallet.dat` aslinya.

**Siapa yang menggunakannya?**
- Pemilik wallet yang lupa password dan ingin memverifikasi kandidat password
- Tim forensik digital
- Peneliti keamanan yang mempelajari kriptografi dompet Bitcoin
- Pelajar yang ingin memahami cara kerja enkripsi wallet

---

## 2. File yang Tersedia

| File | Bahasa | Deskripsi |
|------|--------|-----------|
| `bitcoin-wallet-checker.html` | 🇮🇩 Indonesia | Single checker v1 — verifikasi satu hash + satu password |
| `bitcoin-batch-checker.html` | 🇮🇩 Indonesia | Batch checker v2 — 100+ hash dengan wordlist |
| `bitcoin-batch-checker-en.html` | 🇬🇧 English | Batch checker v2 — versi bahasa Inggris |
| `README-ID.md` | 🇮🇩 Indonesia | Dokumentasi ini |
| `README-EN.md` | 🇬🇧 English | Dokumentasi bahasa Inggris |

---

## 3. Changelog — Riwayat Versi

### 🔖 v1.0 — Single Hash Checker
**File:** `bitcoin-wallet-checker.html`  
**Status:** Stable — Bug-fixed

#### Fitur v1.0
- Input satu hash (`$bitcoin$` atau `$litecoin$`) + satu password
- Tombol toggle show/hide password
- Tampilan debug info (key, IV, ciphertext, hasil dekripsi, padding)
- Validasi format hash dengan pesan error deskriptif
- 100% client-side, tidak ada request ke server

#### Bug yang Ditemukan & Diperbaiki di v1.0

**🐛 Bug #1 — Fungsi helper tidak diimplementasikan** *(Severity: Critical)*
```
Kondisi awal:
  function hexToBytes(hex) { /* ... */ }       // kosong!
  function bytesToHex(bytes) { /* ... */ }     // kosong!
  function uint8ToWordArray(u8) { /* ... */ }  // kosong!
  function wordArrayToUint8(wa) { /* ... */ }  // kosong!

Dampak: Tool langsung crash saat pertama dijalankan.
Fix: Implementasi lengkap semua fungsi konversi.
```

**🐛 Bug #2 — mkHexLen salah diinterpretasikan** *(Severity: Critical)*
```
Kondisi awal:
  if (masterKeyHex.length !== mkLen * 2)  // ← perkalian 2 KELIRU

Contoh: hash $bitcoin$64$... → mkLen=64
  Kode lama mengharapkan: 64 * 2 = 128 hex chars
  Kenyataannya: mkHex hanya 64 chars → ERROR selalu!

Penjelasan: mkHexLen adalah panjang HEX STRING, bukan byte count.
  64 hex chars = 32 bytes (bukan 64 bytes)

Fix: if (masterKeyHex.length !== mkHexLen)  // tanpa *2
```

**🐛 Bug #3 — KDF yang digunakan salah: scrypt bukan SHA-512** *(Severity: Critical)*
```
Kondisi awal:
  const derivedBytes = await scrypt.scrypt(
      new TextEncoder().encode(password),
      saltBytes, N, r, p, dkLen          // ← scrypt! SALAH
  );

Bitcoin Core TIDAK menggunakan scrypt untuk enkripsi wallet.dat.
Bitcoin Core menggunakan SHA-512 iteratif (crypter.cpp).

Dampak: Tool selalu mengembalikan "Password Salah" meskipun
        password yang dimasukkan 100% benar.

Fix: Implementasi SHA-512 iteratif yang benar:
  hash = SHA512(password + salt)   ← round 1
  hash = SHA512(hash)              ← round 2..N
  key = hash[0..31], iv = hash[32..47]
```

**🐛 Bug #4 — Logika validasi XOR tidak berdasar** *(Severity: High)*
```
Kondisi awal:
  // XOR hasil dekripsi dengan IV wallet
  xorResult[i] = decryptedBytes[i] ^ masterKeyBytes[i];
  // Cek apakah semua byte = 0x10
  isValid = xorResult.every(b => b === 0x10);

Ini tidak ada dasar teknisnya sama sekali.

Fix: Gunakan validasi PKCS7 standar (lihat Bug #5 untuk
     penyempurnaan lebih lanjut di v1.1).
```

---

### 🔖 v1.1 — Single Hash Checker (Hotfix)
**File:** `bitcoin-wallet-checker.html` *(update in-place)*  
**Status:** Stable — Hotfix setelah pengujian nyata

#### Latar Belakang v1.1

Setelah v1.0 dirilis, pengujian dengan hash nyata dari wallet saldo nol menemukan **false positive** — tool mengatakan password benar padahal password tersebut salah di Bitcoin Core.

Hash uji: `$bitcoin$64$ff4eb1d0...$16$6b8207637fc796a0$37698$2$00$2$00`  
Password uji: `"2315"` → Tool v1.0 bilang **BENAR** ❌ (seharusnya **SALAH**)

**🐛 Bug #5 — False Positive PKCS7: Padding `0x01` Selalu Lolos** *(Severity: High)*
```
Kondisi di v1.0 (setelah fix Bug #4):
  const last = decryptedBytes[decryptedBytes.length - 1];
  let isValid = (last >= 1 && last <= 16);  // ← terlalu longgar!

Masalah:
  Password salah → dekripsi menghasilkan data acak → last byte = 0x01
  Validasi: 0x01 >= 1 && 0x01 <= 16 → TRUE → false positive!

  Probabilitas false positive: ~6.25% (1 dari 16 kemungkinan)
  Artinya: ~1 dari 16 password salah akan dilaporkan sebagai BENAR.

Akar masalah:
  Bitcoin Core master key SELALU 32 byte (AES-256).
  PKCS7 pada 32 byte data → padding = satu blok penuh = 16 × 0x10
  Hashcat mengambil 2 blok (32 byte) terakhir → blok akhir = semua 0x10

Fix — Validasi ketat Bitcoin-specific:
  let isValid = (last === 0x10);  // harus tepat 0x10
  if (isValid) {
      for (let i = decBytes.length - 16; i < decBytes.length; i++) {
          if (decBytes[i] !== 0x10) { isValid = false; break; }
      }
  }

  Probabilitas false positive setelah fix: ~1/(256^16) ≈ nol
```

---

### 🔖 v2.0 — Batch Checker (Major Release)
**File:** `bitcoin-batch-checker.html` / `bitcoin-batch-checker-en.html`  
**Status:** Stable — Current

#### Fitur Baru v2.0

**⚡ Tab Batch Checker**
- Input daftar hash (100+ sekaligus), satu per baris
- Input wordlist password, satu per baris
- Upload file `.txt` wordlist langsung dari browser
- Progress bar real-time dengan statistik lengkap:
  - Jumlah ditemukan / dicek / sisa
  - Kecepatan (hash/menit)
  - Estimasi waktu selesai (ETA)
- Concurrency engine: proses 1/2/4 kombinasi secara paralel
- Tombol **Pause** — hentikan sementara tanpa kehilangan progres
- Tombol **Stop** — hentikan sepenuhnya kapan saja
- Mode "berhenti saat ditemukan" atau "coba semua password"
- Live log dengan timestamp setiap aktivitas
- Filter hasil tabel: Semua / Ditemukan / Gagal / Error
- Export hasil ke **CSV** (semua hasil atau yang ditemukan saja)
- Copy password yang ditemukan ke clipboard
- Summary cards: total ditemukan, gagal, total hash, waktu

**🔍 Tab Single Check**
- Verifikasi satu hash + satu password
- Identik secara fungsional dengan v1.1
- Semua bug fix sudah termasuk

**📖 Tab Panduan / Guide**
- Dokumentasi format hash inline
- Penjelasan algoritma verifikasi
- Tips penggunaan batch checking

**🌐 Tersedia dalam dua bahasa**
- `bitcoin-batch-checker.html` — Bahasa Indonesia
- `bitcoin-batch-checker-en.html` — Bahasa Inggris

#### Peningkatan Teknis v2.0

| Aspek | v1.x | v2.0 |
|-------|-------|-------|
| Jumlah hash | 1 | 1 — 1000+ |
| Jumlah password | 1 | 1 — tidak terbatas |
| Concurrency | - | 1 / 2 / 4 paralel |
| Progress tracking | - | Real-time dengan ETA |
| Export hasil | - | CSV + clipboard |
| Pause/Stop | - | ✓ |
| Live log | - | ✓ (500 baris buffer) |
| Upload wordlist | - | ✓ (.txt) |
| Bahasa | Indonesia | Indonesia + English |
| Crypto engine | SHA-512 + AES + PKCS7 ketat | Sama, diwariskan |

#### Tidak Ada Perubahan pada Crypto Engine

> Seluruh logika kriptografi (KDF SHA-512 iteratif, AES-256-CBC, validasi padding `0x10×16`) identik antara v1.1 dan v2.0. Tidak ada bug crypto baru yang ditemukan atau diperkenalkan.

---

## 4. Latar Belakang: Bagaimana Bitcoin Core Menyimpan Password?

Ketika kamu mengenkripsi wallet di Bitcoin Core, program tidak langsung mengenkripsi private key dengan passwordmu. Ada beberapa lapisan:

```
┌───────────────────────────────────────────────────────────┐
│                  ARSITEKTUR ENKRIPSI WALLET               │
│                                                           │
│  PASSWORD (teks biasa dari pengguna)                      │
│       │                                                   │
│       ▼                                                   │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  KDF: SHA-512 Iteratif + Salt (N kali iterasi)      │  │
│  │  → Menghasilkan: Key (32 byte) + IV (16 byte)       │  │
│  └─────────────────────────────────────────────────────┘  │
│       │                                                   │
│       ▼                                                   │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  AES-256-CBC Dekripsi pada Master Key Terenkripsi   │  │
│  └─────────────────────────────────────────────────────┘  │
│       │                                                   │
│       ▼                                                   │
│  Master Key (plaintext) → digunakan mengenkripsi          │
│  semua Private Key di dalam wallet                        │
└───────────────────────────────────────────────────────────┘
```

**Konsep Penting:**
- **Master Key** — Kunci rahasia utama untuk mengenkripsi semua private key. Master key ini sendiri dienkripsi menggunakan password pengguna.
- **Salt** — Data acak yang ditambahkan sebelum hashing. Mencegah serangan rainbow table.
- **Iterations (N)** — Berapa kali SHA-512 diulang. Makin besar N, makin lambat brute-force.
- **IV (Initialization Vector)** — Nilai awal untuk mode CBC. Dihasilkan dari KDF, tidak disimpan terpisah.

---

## 5. Format Hash HashCat ($bitcoin$)

Hash dihasilkan oleh `bitcoin2john.py` (paket John the Ripper) yang membaca `wallet.dat`.

### Struktur Format

```
$bitcoin$<mkHexLen>$<mkHex>$<saltHexLen>$<saltHex>$<iterations>$<f1>$<f2>$<f3>$<f4>
```

### Tabel Penjelasan Field

| Posisi | Nama Field    | Tipe    | Keterangan |
|--------|--------------|---------|------------|
| [0]    | `mkHexLen`   | integer | **Panjang STRING hex** masterKey — bukan byte count! |
| [1]    | `mkHex`      | hex     | Master Key terenkripsi dalam hex |
| [2]    | `saltHexLen` | integer | **Panjang STRING hex** salt — bukan byte count! |
| [3]    | `saltHex`    | hex     | Salt dalam hex |
| [4]    | `iterations` | integer | Jumlah iterasi SHA-512 |
| [5..8] | (extra)      | —       | Field tambahan, tidak dipakai verifikasi |

### Contoh Hash Nyata

```
$bitcoin$64$617c4b22fabd578e0f4d030245a0cbebd9da426fbee49c2feb885fa190b65096$16$dff2b89e4d885c28$35714$2$00$2$00
```

Dipecah:
```
Prefix      : $bitcoin$
mkHexLen    : 64   → mkHex sepanjang 64 hex chars = 32 bytes
mkHex       : 617c4b22fabd578e0f4d030245a0cbebd9da426fbee49c2feb885fa190b65096
saltHexLen  : 16   → saltHex sepanjang 16 hex chars = 8 bytes
saltHex     : dff2b89e4d885c28
iterations  : 35714
```

### ⚠️ Jebakan Umum — mkHexLen Bukan Byte Count!

```
SALAH ❌:  panjang_diharapkan = mkHexLen * 2
           → 64 * 2 = 128 hex chars (keliru!)

BENAR ✅:  panjang_diharapkan = mkHexLen
           → 64 hex chars (tepat!)
```

`mkHexLen` adalah jumlah **karakter hex**, bukan jumlah byte. Karena 1 byte = 2 hex chars, maka `mkHexLen=64` artinya 64 hex chars = 32 bytes.

---

## 6. Alur Kerja Verifikasi — Langkah demi Langkah

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
│  Ulang N kali            │
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
│  semua harus = 0x10?     │
└──────────┬───────────────┘
           │
     ┌─────┴──────┐
     ▼            ▼
  YA ✅        TIDAK ❌
"Password    "Password
  Benar!"      Salah!"
```

---

## 7. KDF: SHA-512 Iteratif (Inti dari Segalanya)

KDF = **Key Derivation Function** — fungsi untuk menurunkan kunci kriptografi dari password teks biasa.

### Algoritma Bitcoin Core (crypter.cpp)

```
ROUND 1:
  data = bytes(password) + bytes(salt)
  hash = SHA-512(data)              ← 64 byte

ROUND 2 hingga N:
  hash = SHA-512(hash)              ← hanya hash sebelumnya!

HASIL AKHIR (64 byte):
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

    // Round 1: SHA-512(password + salt)
    let hashBuf = await crypto.subtle.digest('SHA-512', combined);

    // Round 2..N: SHA-512(hash sebelumnya saja)
    for (let i = 1; i < iterations; i++) {
        hashBuf = await crypto.subtle.digest('SHA-512', hashBuf);
    }

    return new Uint8Array(hashBuf); // 64 bytes
}
```

### Visualisasi Iterasi

```
Iterasi   Input                          Output
───────── ────────────────────────────── ──────────────────
1         SHA-512(password + salt)    →  hash₁  (64 byte)
2         SHA-512(hash₁)              →  hash₂  (64 byte)
3         SHA-512(hash₂)              →  hash₃  (64 byte)
...       ...                            ...
N         SHA-512(hash_{N-1})         →  hashₙ  (64 byte)

key = hashₙ[0..31]   (32 byte)
iv  = hashₙ[32..47]  (16 byte)
```

### Mengapa Perlu Iterasi?

Tanpa iterasi, penyerang bisa mencoba jutaan password per detik di GPU. Dengan `iterations = 35714`, setiap percobaan membutuhkan 35.714 komputasi SHA-512 — memperlambat brute-force secara signifikan.

> **Analogi:** Seperti mengunci pintu dengan 35.714 kunci yang harus dibuka satu per satu secara berurutan.

---

## 8. Enkripsi AES-256-CBC

### AES (Advanced Encryption Standard)

AES adalah algoritma enkripsi simetris standar industri. Simetris = kunci yang sama untuk enkripsi dan dekripsi.

- **AES-256**: Kunci 256-bit (32 byte)
- **CBC (Cipher Block Chaining)**: Mode operasi yang menghubungkan blok-blok data

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

IV memastikan plaintext yang sama menghasilkan ciphertext berbeda setiap enkripsi. Dalam Bitcoin Core, IV tidak disimpan terpisah — dihasilkan ulang dari KDF setiap kali dibutuhkan.

---

## 9. Validasi PKCS7 Padding

### Mengapa Perlu Padding?

AES-CBC bekerja pada blok 16 byte. Jika data tidak kelipatan 16, ditambahkan padding.

### Skema PKCS7

```
Data kurang N byte untuk genap 16 → tambahkan N byte bernilai N

Contoh (kurang 3 byte):
  [data asli...]  03 03 03

Kasus Bitcoin (data 32 byte = kelipatan 16 → full block padding):
  [32 byte data]  10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
                  ↑ 0x10 = 16 decimal, 16 kali
```

### Validasi Ketat Bitcoin

```javascript
// ❌ VALIDASI LONGGAR — rentan false positive (~6.25%):
const last = decryptedBytes[decryptedBytes.length - 1];
let isValid = (last >= 1 && last <= 16);  // 0x01 selalu lolos!

// ✅ VALIDASI KETAT — Bitcoin-specific (false positive ~0):
let isValid = (last === 0x10);  // harus tepat 0x10
if (isValid) {
    for (let i = decryptedBytes.length - 16; i < decryptedBytes.length; i++) {
        if (decryptedBytes[i] !== 0x10) { isValid = false; break; }
    }
}
```

**Mengapa harus tepat `0x10`?** Karena master key Bitcoin selalu 32 byte (AES-256), dan PKCS7 pada data 32 byte = satu blok padding penuh = 16 × `0x10`.

---

## 10. Bug yang Ditemukan & Diperbaiki (Semua Versi)

Ringkasan semua bug dari v1.0 hingga v1.1, beserta status penyelesaiannya:

| # | Bug | Severity | Versi Ditemukan | Versi Fix | Status |
|---|-----|----------|-----------------|-----------|--------|
| 1 | Fungsi helper tidak diimplementasikan | Critical | v1.0 awal | v1.0 | ✅ Fixed |
| 2 | `mkHexLen` dikali 2 — interpretasi salah | Critical | v1.0 awal | v1.0 | ✅ Fixed |
| 3 | KDF salah: scrypt dipakai bukan SHA-512 | Critical | v1.0 awal | v1.0 | ✅ Fixed |
| 4 | Logika validasi XOR tidak berdasar | High | v1.0 awal | v1.0 | ✅ Fixed |
| 5 | False positive PKCS7: padding `0x01` lolos | High | v1.0 (pengujian nyata) | v1.1 | ✅ Fixed |

Detail lengkap setiap bug ada di bagian [Changelog](#3-changelog--riwayat-versi).

---

## 11. Cara Mendapatkan Hash dari wallet.dat

### Menggunakan bitcoin2john.py

```bash
# Install dependensi
pip install bsddb3

# Ekstrak hash
python bitcoin2john.py /path/to/wallet.dat
```

Output:
```
wallet.dat:$bitcoin$64$xxxxx$16$xxxxx$25000$2$00$2$00
```

Bagian setelah `:` adalah hash yang dimasukkan ke tool ini.

### Menggunakan hashcat (Referensi Edukasi)

```bash
# Mode -m 11300 = Bitcoin/Litecoin wallet.dat
hashcat -m 11300 hash.txt wordlist.txt

# Dengan rules
hashcat -m 11300 hash.txt wordlist.txt -r rules/best64.rule
```

> **Penting:** Gunakan hanya pada wallet milik sendiri atau dengan izin resmi tertulis.

---

## 12. Penjelasan Kode per Fungsi

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
CryptoJS menggunakan format `WordArray` (array 32-bit integer, big-endian). Fungsi ini mengkonversi `Uint8Array` standar ke format tersebut.

```javascript
function uint8ToWordArray(u8) {
    const words = [];
    for (let i = 0; i < u8.length; i += 4)
        words.push(
            ((u8[i]   || 0) << 24) |  // byte ke-1 → bit 31-24
            ((u8[i+1] || 0) << 16) |  // byte ke-2 → bit 23-16
            ((u8[i+2] || 0) <<  8) |  // byte ke-3 → bit 15-8
            ((u8[i+3] || 0))          // byte ke-4 → bit 7-0
        );
    return CryptoJS.lib.WordArray.create(words, u8.length);
}
```

### `parseBitcoinHash(hashStr)`
```javascript
function parseBitcoinHash(hashStr) {
    // Input: "$bitcoin$64$617c4b22...96$16$dff2b89e4d885c28$35714$2$00$2$00"
    const parts = hashStr.slice("$bitcoin$".length).split('$');
    // parts: ["64", "617c4b22...96", "16", "dff2b89e4d885c28", "35714", ...]

    const mkHexLen   = parseInt(parts[0]);  // 64
    const masterKey  = parts[1];            // 64 chars hex
    const saltHexLen = parseInt(parts[2]);  // 16
    const saltHex    = parts[3];            // 16 chars hex
    const iterations = parseInt(parts[4]);  // 35714

    // KUNCI: validasi langsung tanpa *2
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

    // Round 1: SHA-512(password + salt)
    let hashBuf = await crypto.subtle.digest('SHA-512', combined);

    // Round 2..N: SHA-512(hash saja)
    for (let i = 1; i < iterations; i++)
        hashBuf = await crypto.subtle.digest('SHA-512', hashBuf);

    // key = [0..31], iv = [32..47]
    return new Uint8Array(hashBuf);
}
```

---

## 13. Perbandingan: SHA-512 Iteratif vs PBKDF2 vs scrypt

| Kriteria | SHA-512 Iteratif | PBKDF2-SHA512 | scrypt |
|----------|-----------------|---------------|--------|
| **Dibuat tahun** | ~2009 | 2000 (RFC 2898) | 2009 |
| **Tahan GPU?** | Rendah | Rendah-Sedang | Tinggi (memory-hard) |
| **Tahan ASIC?** | Tidak | Tidak | Ya |
| **Kompleksitas** | Sangat sederhana | Sedang | Kompleks |
| **Parameter** | iterations saja | iter, keyLen | N, r, p, keyLen |
| **Digunakan di Bitcoin** | wallet.dat enkripsi | BIP39 seed | Litecoin mining |
| **Output size** | 64 byte tetap | Variable | Variable |
| **Standar modern?** | Tidak (usang) | Diterima | Sangat dianjurkan |

**Kesimpulan:** SHA-512 iteratif di Bitcoin Core adalah warisan desain 2009. Untuk sistem baru, gunakan PBKDF2 atau **Argon2** (pemenang Password Hashing Competition 2015).

---

## 14. Keamanan & Etika Penggunaan

### ✅ Penggunaan yang Diizinkan
- Memverifikasi password wallet milik sendiri
- Penelitian keamanan dengan izin tertulis dari pemilik
- Pembelajaran dan edukasi kriptografi
- Forensik digital dengan surat perintah resmi

### ❌ Penggunaan yang Dilarang
- Mengakses wallet orang lain tanpa izin
- Brute-force terhadap wallet bukan milikmu
- Segala bentuk pencurian aset digital

### 🔒 Privasi Tool Ini

Tool ini **100% client-side**. Semua komputasi terjadi di browser. Tidak ada data (hash, password, hasil) yang dikirim ke server manapun. Verifikasi dengan memantau Network tab di browser DevTools.

---

## 15. Referensi & Bacaan Lanjutan

| Sumber | Keterangan |
|--------|-----------|
| `src/wallet/crypter.cpp` (Bitcoin Core) | Implementasi asli KDF dan enkripsi wallet |
| RFC 2898 | Spesifikasi PBKDF2 |
| FIPS 197 | Spesifikasi AES |
| RFC 2315 | Spesifikasi PKCS7 padding |
| `bitcoin2john.py` (John the Ripper) | Ekstrak hash dari wallet.dat |
| Hashcat mode 11300 | Dokumentasi format hash Bitcoin wallet |

### Topik Lanjutan

- **BIP32/BIP39** — Hierarchical Deterministic Wallets dan mnemonic seed phrase
- **BIP38** — Enkripsi private key dengan scrypt (berbeda dari wallet.dat!)
- **Argon2** — KDF modern pemenang Password Hashing Competition 2015
- **HSM (Hardware Security Module)** — Penyimpanan kunci kriptografi enterprise

---

## Penutup

Tool dan dokumentasi ini dibuat dengan tujuan **edukasi** — membantu pelajar dan profesional memahami cara kerja kriptografi nyata di balik dompet Bitcoin. Memahami bug dalam implementasi yang salah mengajarkan bahwa kriptografi yang "hampir benar" sama berbahayanya dengan tidak menggunakan kriptografi sama sekali.

Selamat belajar! 🚀

---

## Donasi

### Jika alat ini bermanfaat untuk pendidikan dan pembelajaran Anda, donasi sangat dihargai:

- **Bitcoin (BTC)** — bc1qn6t8hy8memjfzp4y3sh6fvadjdtqj64vfvlx58
- **Ethereum (ETH)** — 0x512936ca43829C8f71017aE47460820Fe703CAea
- **Solana (SOL)** — 6ZZrRmeGWMZSmBnQFWXG2UJauqbEgZnwb4Ly9vLYr7mi
- **PayPal:** — syabiz@yandex.com

Donasi akan digunakan untuk pengembangan fitur baru, pemeliharaan server, dan dokumentasi.

---

## Kontak

- **Masalah GitHub:** https://github.com/syabiz/Bitcoin-Wallet-Checker/issues
- **Email:** syabiz@yandex.com
- **Twitter:** @syabiz

---

Terima kasih telah menggunakan Alat Pemeriksa Dompet Bitcoin! 🚀
*Dibuat dengan ❤️ untuk pendidikan dan pembelajaran Bitcoin*

*Terakhir diperbarui: 19 Februari 2026*

---

*Dibuat untuk keperluan edukasi internal. Harap digunakan secara bertanggung jawab.*

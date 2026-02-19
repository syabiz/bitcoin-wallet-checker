# Bitcoin Wallet Checker

> *Bitcoin & Litecoin · HashCat Format · SHA-512 + AES-256-CBC**
> Enter the hash in HashCat format "$bitcoin$..." and the password you want to verify. The process is done entirely in the browser (client-side).

---

## 📋 Daftar Isi

1. [Apa Itu Tool Ini?](#1-apa-itu-tool-ini)
2. [Latar Belakang: Bagaimana Bitcoin Core Menyimpan Password?](#2-latar-belakang-bagaimana-bitcoin-core-menyimpan-password)
3. [Format Hash HashCat ($bitcoin$)](#3-format-hash-hashcat-bitcoin)
4. [Alur Kerja Verifikasi — Langkah demi Langkah](#4-alur-kerja-verifikasi--langkah-demi-langkah)
5. [KDF: SHA-512 Iteratif (Inti dari Segalanya)](#5-kdf-sha-512-iteratif-inti-dari-segalanya)
6. [Enkripsi AES-256-CBC](#6-enkripsi-aes-256-cbc)
7. [Validasi PKCS7 Padding](#7-validasi-pkcs7-padding)
8. [Kesalahan Umum & Bug yang Sudah Diperbaiki](#8-kesalahan-umum--bug-yang-sudah-diperbaiki)
9. [Cara Mendapatkan Hash dari wallet.dat](#9-cara-mendapatkan-hash-dari-walletdat)
10. [Penjelasan Kode per Fungsi](#10-penjelasan-kode-per-fungsi)
11. [Perbandingan: SHA-512 Iteratif vs PBKDF2 vs scrypt](#11-perbandingan-sha-512-iteratif-vs-pbkdf2-vs-scrypt)
12. [Keamanan & Etika Penggunaan](#12-keamanan--etika-penggunaan)
13. [Referensi & Bacaan Lanjutan](#13-referensi--bacaan-lanjutan)

---

## 1. Apa Itu Tool Ini?

Tool ini adalah **verifikator password** untuk file `wallet.dat` milik Bitcoin Core (dan Litecoin Core). Tool bekerja sepenuhnya di **browser** (client-side) — tidak ada data yang dikirim ke server.

**Fungsi utama:**
Menerima sebuah hash dalam format HashCat (`$bitcoin$...`) dan sebuah password, lalu memverifikasi apakah password tersebut benar atau salah — **tanpa perlu membuka file wallet.dat aslinya**.

**Siapa yang menggunakannya?**
- Pemilik wallet yang lupa password dan ingin memverifikasi kandidat password
- Tim forensik digital
- Peneliti keamanan yang mempelajari kriptografi dompet Bitcoin
- Pelajar yang ingin memahami cara kerja enkripsi wallet

---

## 2. Latar Belakang: Bagaimana Bitcoin Core Menyimpan Password?

Ketika kamu mengenkripsi wallet di Bitcoin Core, program tidak langsung mengenkripsi private key dengan passwordmu. Ada beberapa lapisan:

```
┌─────────────────────────────────────────────────────────────┐
│                    ARSITEKTUR ENKRIPSI WALLET                │
│                                                             │
│  PASSWORD (teks biasa dari pengguna)                        │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  KDF: SHA-512 Iteratif + Salt (N kali iterasi)      │   │
│  │  → Menghasilkan: Key (32 byte) + IV (16 byte)       │   │
│  └─────────────────────────────────────────────────────┘   │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  AES-256-CBC Dekripsi pada Master Key Terenkripsi   │   │
│  └─────────────────────────────────────────────────────┘   │
│       │                                                     │
│       ▼                                                     │
│  Master Key (plaintext) → digunakan mengenkripsi           │
│  semua Private Key di dalam wallet                          │
└─────────────────────────────────────────────────────────────┘
```

**Konsep Penting:**
- **Master Key**: Kunci rahasia utama yang dipakai untuk mengenkripsi private key. Master key ini sendiri dienkripsi menggunakan password pengguna.
- **Salt**: Data acak yang ditambahkan sebelum proses hashing. Tujuannya mencegah serangan rainbow table.
- **Iterations (N)**: Berapa kali proses SHA-512 diulang. Makin besar N, makin lambat proses brute-force.
- **IV (Initialization Vector)**: Nilai awal untuk mode CBC. Dihasilkan dari KDF, bukan disimpan terpisah.

---

## 3. Format Hash HashCat ($bitcoin$)

Hash dihasilkan oleh tool `bitcoin2john.py` (dari paket John the Ripper) yang membaca file `wallet.dat`.

### Struktur Format

```
$bitcoin$<mkHexLen>$<mkHex>$<saltHexLen>$<saltHex>$<iterations>$<f1>$<f2>$<f3>$<f4>
```

### Tabel Penjelasan Field

| Posisi | Nama Field   | Tipe    | Keterangan                                              |
|--------|-------------|---------|----------------------------------------------------------|
| [0]    | `mkHexLen`  | integer | **Panjang STRING hex** dari masterKey (bukan byte count!) |
| [1]    | `mkHex`     | hex     | Master Key terenkripsi (dalam format hex)               |
| [2]    | `saltHexLen`| integer | **Panjang STRING hex** dari salt (bukan byte count!)    |
| [3]    | `saltHex`   | hex     | Salt dalam format hex                                   |
| [4]    | `iterations`| integer | Jumlah iterasi SHA-512                                  |
| [5..8] | (extra)     | -       | Field tambahan, tidak digunakan dalam verifikasi dasar  |

### Contoh Hash Nyata

```
$bitcoin$64$617c4b22fabd578e0f4d030245a0cbebd9da426fbee49c2feb885fa190b65096$16$dff2b89e4d885c28$35714$2$00$2$00
```

Dipecah:
```
Prefix      : $bitcoin$
mkHexLen    : 64       → mkHex sepanjang 64 hex chars = 32 bytes
mkHex       : 617c4b22fabd578e0f4d030245a0cbebd9da426fbee49c2feb885fa190b65096
saltHexLen  : 16       → saltHex sepanjang 16 hex chars = 8 bytes
saltHex     : dff2b89e4d885c28
iterations  : 35714
```

### ⚠️ Jebakan Umum — mkHexLen Bukan Byte Count!

Ini adalah **kesalahan paling sering** dibuat oleh implementor:

```
SALAH ❌:  panjang_yang_diharapkan = mkHexLen * 2
           → 64 * 2 = 128 hex chars (keliru!)

BENAR ✅:  panjang_yang_diharapkan = mkHexLen
           → 64 hex chars (tepat!)
```

Mengapa salah? Karena orang mengira `mkHexLen` adalah **jumlah byte**, padahal sebenarnya adalah **jumlah karakter hex**. 1 byte = 2 karakter hex. Jadi `mkHexLen=64` artinya 64 karakter hex = 32 byte.

---

## 4. Alur Kerja Verifikasi — Langkah demi Langkah

```
INPUT: hash ($bitcoin$...) + password (teks)
           │
           ▼
┌─────────────────────────────┐
│  LANGKAH 1: Parse Hash      │
│  Ekstrak: mkHex, saltHex,   │
│  iterations                 │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  LANGKAH 2: KDF             │
│  SHA-512 Iteratif           │
│  Input: password + salt     │
│  Ulang N kali               │
│  Output: 64 byte            │
│  → key = byte[0..31]        │
│  → iv  = byte[32..47]       │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  LANGKAH 3: Dekripsi AES    │
│  AES-256-CBC                │
│  Key = 32 byte dari KDF     │
│  IV  = 16 byte dari KDF     │
│  Data = mkHex[0..31] (32b)  │
│  Output: plaintext 32 byte  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  LANGKAH 4: Cek Padding     │
│  PKCS7: byte terakhir = N?  │
│  N byte terakhir semua = N? │
└─────────────┬───────────────┘
              │
        ┌─────┴──────┐
        ▼            ▼
   VALID ✅      TIDAK VALID ❌
  "Password    "Password
    Benar!"      Salah!"
```

---

## 5. KDF: SHA-512 Iteratif (Inti dari Segalanya)

KDF = **Key Derivation Function** — fungsi untuk menurunkan kunci kriptografi dari password teks biasa.

### Algoritma Bitcoin Core (crypter.cpp)

```
ROUND 1:
  data  = bytes(password) + bytes(salt)
  hash  = SHA-512(data)           ← 64 byte hasil

ROUND 2 hingga N:
  hash  = SHA-512(hash)           ← hanya hash sebelumnya!

HASIL AKHIR (64 byte):
  key = hash[0 .. 31]             ← 32 byte untuk AES-256
  iv  = hash[32 .. 47]            ← 16 byte untuk AES CBC
```

### Implementasi JavaScript (Web Crypto API)

```javascript
async function deriveKeyBitcoinSHA512(password, saltBytes, iterations) {
    const passBytes = new TextEncoder().encode(password);

    // Gabungkan password + salt menjadi satu array
    const combined = new Uint8Array(passBytes.length + saltBytes.length);
    combined.set(passBytes, 0);
    combined.set(saltBytes, passBytes.length);

    // Round 1: SHA-512(password + salt)
    let hashBuf = await crypto.subtle.digest('SHA-512', combined);

    // Round 2 hingga N: SHA-512(hash sebelumnya)
    for (let i = 1; i < iterations; i++) {
        hashBuf = await crypto.subtle.digest('SHA-512', hashBuf);
    }

    return new Uint8Array(hashBuf); // 64 bytes
}
```

### Visualisasi Iterasi

```
Iterasi  Input                        Output
──────── ──────────────────────────── ──────────────────────────────
1        SHA-512(password + salt)  →  hash₁  (64 byte)
2        SHA-512(hash₁)            →  hash₂  (64 byte)
3        SHA-512(hash₂)            →  hash₃  (64 byte)
...      ...                          ...
N        SHA-512(hash_{N-1})       →  hashₙ  (64 byte) ← hasil akhir

key = hashₙ[0..31]   (32 byte)
iv  = hashₙ[32..47]  (16 byte)
```

### Mengapa Perlu Iterasi?

Tanpa iterasi, penyerang bisa mencoba jutaan password per detik di GPU modern. Dengan `iterations = 35714`, setiap percobaan password membutuhkan 35.714 kali komputasi SHA-512. Ini memperlambat brute-force secara signifikan.

> **Analogi:** Seperti mengunci pintu tidak hanya dengan satu kunci, tapi dengan 35.714 kunci yang harus dibuka satu per satu secara berurutan.

---

## 6. Enkripsi AES-256-CBC

### AES (Advanced Encryption Standard)

AES adalah algoritma enkripsi simetris standar industri. Simetris artinya kunci yang sama digunakan untuk enkripsi dan dekripsi.

- **AES-256**: Menggunakan kunci 256-bit (32 byte)
- **CBC (Cipher Block Chaining)**: Mode operasi yang menghubungkan blok-blok data

### Cara Kerja CBC

```
ENKRIPSI:
  Plaintext₁  XOR  IV   → AES(key) → Ciphertext₁
  Plaintext₂  XOR  C₁   → AES(key) → Ciphertext₂
  Plaintext₃  XOR  C₂   → AES(key) → Ciphertext₃

DEKRIPSI (kebalikannya):
  AES_decrypt(key, C₁) XOR IV  → Plaintext₁
  AES_decrypt(key, C₂) XOR C₁ → Plaintext₂
  AES_decrypt(key, C₃) XOR C₂ → Plaintext₃
```

### Mengapa IV Penting?

IV (Initialization Vector) memastikan bahwa plaintext yang sama akan menghasilkan ciphertext yang berbeda setiap kali dienkripsi (selama IV berbeda). Ini mencegah analisis pola.

Dalam Bitcoin Core, IV **tidak disimpan terpisah** — melainkan dihasilkan ulang dari KDF setiap kali dibutuhkan. Inilah mengapa kita hanya perlu password dan salt untuk mendekripsi.

### Implementasi JavaScript

```javascript
const decrypted = CryptoJS.AES.decrypt(
    { ciphertext: uint8ToWordArray(cipherBytes) },  // data terenkripsi
    uint8ToWordArray(key),                           // kunci 32 byte
    {
        iv:      uint8ToWordArray(iv),               // IV 16 byte
        mode:    CryptoJS.mode.CBC,                  // mode CBC
        padding: CryptoJS.pad.NoPadding              // padding dihandle manual
    }
);
```

---

## 7. Validasi PKCS7 Padding

### Mengapa Perlu Padding?

AES-CBC bekerja pada blok 16 byte. Jika plaintext tidak habis dibagi 16, harus ditambahkan padding (tambahan byte) agar pas.

### Skema PKCS7

```
Jika data kurang N byte untuk genap 16:
  Tambahkan N byte, masing-masing bernilai N

Contoh:
  Data = 13 byte → kurang 3 byte
  Padding: 03 03 03
  Data lengkap = [data asli] 03 03 03

Kasus khusus: Data sudah kelipatan 16:
  Padding = 1 blok penuh: 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
  (0x10 = 16 dalam desimal)
```

### Logika Validasi dalam Kode

```javascript
const last = decryptedBytes[decryptedBytes.length - 1]; // ambil byte terakhir

let isValid = (last >= 1 && last <= 16); // nilai harus 1-16

if (isValid) {
    // Periksa: apakah `last` byte terakhir semuanya bernilai `last`?
    for (let i = decryptedBytes.length - last; i < decryptedBytes.length; i++) {
        if (decryptedBytes[i] !== last) {
            isValid = false;
            break;
        }
    }
}
```

### Mengapa Padding Jadi Alat Verifikasi?

Jika password **benar** → dekripsi menghasilkan plaintext asli → padding PKCS7 valid.  
Jika password **salah** → dekripsi menghasilkan data acak → kemungkinan besar padding tidak valid.

```
Password Benar:
  Plaintext: [data master key...]  10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
                                   ↑ semua 0x10 → PKCS7 valid ✅

Password Salah:
  Hasil dekripsi acak: [noise...] 7a 3f b2 91 ...
                                   ↑ tidak ada pola padding → TIDAK valid ❌
```

> **Catatan:** Ada kemungkinan kecil (1/256 per byte) data acak kebetulan membentuk padding valid. Ini disebut "false positive" dan sangat jarang terjadi dalam praktik.

---

## 8. Kesalahan Umum & Bug yang Sudah Diperbaiki

Berikut adalah tiga bug kritis yang ditemukan dan diperbaiki dalam pengembangan tool ini. Ini adalah pelajaran berharga bagi siapapun yang mengimplementasikan hal serupa.

---

### Bug #1 — Fungsi Helper Tidak Diimplementasikan

**Masalah:**
```javascript
// Kode lama (RUSAK):
function hexToBytes(hex) { /* ... */ }      // ← kosong!
function bytesToHex(bytes) { /* ... */ }    // ← kosong!
function uint8ToWordArray(u8) { /* ... */ } // ← kosong!
function wordArrayToUint8(wa) { /* ... */ } // ← kosong!
```

Fungsi-fungsi ini dipanggil di seluruh kode tapi tidak pernah diimplementasikan. Akibatnya tool langsung error saat pertama dijalankan.

**Solusi:** Implementasikan semua fungsi konversi dengan benar.

---

### Bug #2 — `mkHexLen` Diinterpretasikan Salah (Penyebab Error Pengguna)

**Masalah:**
```javascript
// Kode lama (SALAH):
if (masterKeyHex.length !== mkLen * 2) {  // ← perkalian 2 ini KELIRU
    throw new Error("Panjang masterKey tidak sesuai...");
}

// Untuk hash: $bitcoin$64$...
// mkLen = 64
// Kode lama mengharapkan: 64 * 2 = 128 hex chars
// Kenyataannya mkHex hanya 64 chars → ERROR!
```

**Penjelasan mendalam:**

Di format bitcoin2john, angka setelah `$bitcoin$` adalah **panjang hex string**, bukan jumlah byte. Kebanyakan programmer salah mengasumsikan ini adalah byte count, lalu mengalikan 2 (karena 1 byte = 2 hex chars).

```
Format: $bitcoin$64$[64 karakter hex]...
                 ↑
                 Ini = 64 karakter hex = 32 byte
                 BUKAN = 64 byte = 128 karakter hex!
```

**Solusi:**
```javascript
// Kode baru (BENAR):
if (masterKeyHex.length !== mkHexLen) {  // ← langsung bandingkan, tanpa *2
    throw new Error(`Panjang mkHex tidak sesuai...`);
}
```

---

### Bug #3 — Menggunakan scrypt, Bukan SHA-512 (Bug Logika Paling Serius)

**Masalah:**

Kode lama menggunakan library `scrypt-js` untuk key derivation:

```javascript
// Kode lama (SALAH):
const derivedBytes = await scrypt.scrypt(
    new TextEncoder().encode(password),
    saltBytes,
    N, r, p, dkLen   // scrypt parameters
);
```

**Mengapa ini salah?**

Bitcoin Core **tidak menggunakan scrypt** untuk enkripsi wallet biasa. Bitcoin Core menggunakan **SHA-512 iteratif** yang jauh lebih sederhana (lihat `src/wallet/crypter.cpp`).

scrypt memang digunakan di beberapa tempat terkait Bitcoin (misalnya: mining Litecoin, beberapa implementasi BIP39), tapi **bukan** untuk enkripsi wallet.dat default.

Akibat dari bug ini: tool selalu mengembalikan "Password Salah" meskipun password yang dimasukkan 100% benar. Ini adalah bug yang sangat berbahaya karena tidak menampilkan error — hanya memberikan hasil yang keliru.

**Perbandingan:**

| Aspek            | scrypt                          | SHA-512 Iteratif (Bitcoin Core) |
|------------------|---------------------------------|---------------------------------|
| Fungsi           | `scrypt(pass, salt, N, r, p)`   | `SHA512(SHA512(...SHA512(pass+salt)))` |
| Kompleksitas     | Tinggi (memory-hard)            | Sederhana                       |
| Digunakan di     | Litecoin mining, BIP39 tertentu | Bitcoin Core wallet enkripsi    |
| Output           | Variable length                 | 64 byte tetap                   |

**Solusi:**
```javascript
// Kode baru (BENAR):
async function deriveKeyBitcoinSHA512(password, saltBytes, iterations) {
    const combined = gabungkan(password_bytes + salt_bytes);
    let hash = SHA512(combined);              // round 1
    for (let i = 1; i < iterations; i++) {
        hash = SHA512(hash);                  // round 2..N
    }
    return hash; // key=hash[0..31], iv=hash[32..47]
}
```

---

### Bug #4 — Validasi Padding dengan XOR (Logika Keliru)

**Masalah:**
```javascript
// Kode lama (SALAH):
const xorResult = new Uint8Array(16);
for (let i = 0; i < 16; i++) {
    xorResult[i] = decryptedBytes[i] ^ masterKeyBytes[i]; // XOR dengan IV!
}
// Cek apakah semua byte = 0x10
let isValid = xorResult.every(b => b === 0x10);
```

Logika ini tidak ada dasar teknisnya. XOR hasil dekripsi dengan IV wallet tidak menghasilkan informasi yang berguna untuk validasi.

**Solusi:** Gunakan validasi PKCS7 standar yang sudah dijelaskan di bagian 7.

---

## 9. Cara Mendapatkan Hash dari wallet.dat

Untuk menggunakan tool ini, kamu perlu mengekstrak hash dari file `wallet.dat` terlebih dahulu.

### Menggunakan bitcoin2john.py

```bash
# Install dependensi
pip install bsddb3

# Ekstrak hash
python bitcoin2john.py /path/to/wallet.dat
```

Output yang dihasilkan akan berbentuk:
```
wallet.dat:$bitcoin$64$xxxxx$16$xxxxx$25000$2$00$2$00
```

Bagian setelah `:` adalah hash yang dimasukkan ke tool ini.

### Menggunakan hashcat untuk Crack (Referensi Edukasi)

```bash
# Mode -m 11300 = Bitcoin/Litecoin wallet.dat
hashcat -m 11300 hash.txt wordlist.txt

# Dengan rules
hashcat -m 11300 hash.txt wordlist.txt -r rules/best64.rule
```

> **Penting:** Gunakan hanya pada wallet milikmu sendiri atau dengan izin resmi yang tertulis.

---

## 10. Penjelasan Kode per Fungsi

### `hexToBytes(hex)` — Konversi Hex ke Byte

```javascript
function hexToBytes(hex) {
    // Contoh input:  "dff2b89e"
    // Contoh output: Uint8Array([0xdf, 0xf2, 0xb8, 0x9e])

    hex = hex.replace(/\s+/g, '');  // hapus whitespace
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        //         ↑ ambil 2 karakter, parse sebagai hex
    }
    return bytes;
}
```

### `uint8ToWordArray(u8)` — Konversi untuk CryptoJS

CryptoJS menggunakan format internal `WordArray` (array 32-bit integers, big-endian). Fungsi ini mengkonversi `Uint8Array` standar ke format tersebut.

```javascript
function uint8ToWordArray(u8) {
    const words = [];
    for (let i = 0; i < u8.length; i += 4) {
        // Gabungkan 4 byte menjadi 1 integer 32-bit (big-endian)
        words.push(
            ((u8[i]   || 0) << 24) |  // byte pertama  → bit 31-24
            ((u8[i+1] || 0) << 16) |  // byte kedua    → bit 23-16
            ((u8[i+2] || 0) <<  8) |  // byte ketiga   → bit 15-8
            ((u8[i+3] || 0))          // byte keempat  → bit 7-0
        );
    }
    return CryptoJS.lib.WordArray.create(words, u8.length);
}
```

### `parseBitcoinHash(hashStr)` — Parser Hash

```javascript
function parseBitcoinHash(hashStr) {
    // Contoh input:
    // "$bitcoin$64$617c4b22...96$16$dff2b89e4d885c28$35714$2$00$2$00"

    // Split: ["64", "617c4b22...96", "16", "dff2b89e4d885c28", "35714", ...]
    const parts = hashStr.slice("$bitcoin$".length).split('$');

    const mkHexLen   = parseInt(parts[0]);  // 64
    const masterKey  = parts[1];            // "617c4b22...96" (64 chars)
    const saltHexLen = parseInt(parts[2]);  // 16
    const saltHex    = parts[3];            // "dff2b89e4d885c28" (16 chars)
    const iterations = parseInt(parts[4]);  // 35714

    // Validasi: parts[1] harus sepanjang parts[0] chars (BUKAN parts[0]*2!)
    if (masterKey.length !== mkHexLen) throw new Error("...");

    return { masterKeyHex: masterKey, saltHex, iterations };
}
```

### `deriveKeyBitcoinSHA512(password, saltBytes, iterations)` — KDF Utama

```javascript
async function deriveKeyBitcoinSHA512(password, saltBytes, iterations) {
    // Langkah 1: Encode password ke bytes (UTF-8)
    const passBytes = new TextEncoder().encode(password);

    // Langkah 2: Gabungkan password + salt
    const combined = new Uint8Array(passBytes.length + saltBytes.length);
    combined.set(passBytes, 0);
    combined.set(saltBytes, passBytes.length);

    // Langkah 3: SHA-512 round pertama (dengan pass+salt)
    let hashBuf = await crypto.subtle.digest('SHA-512', combined);

    // Langkah 4: SHA-512 iterasi ke-2 hingga N (hanya hash saja)
    for (let i = 1; i < iterations; i++) {
        hashBuf = await crypto.subtle.digest('SHA-512', hashBuf);
    }

    // Output: 64 byte
    // [0..31]  = AES-256 key
    // [32..47] = CBC IV
    return new Uint8Array(hashBuf);
}
```

---

## 11. Perbandingan: SHA-512 Iteratif vs PBKDF2 vs scrypt

| Kriteria              | SHA-512 Iteratif (Bitcoin Core) | PBKDF2-SHA512     | scrypt              |
|-----------------------|----------------------------------|-------------------|---------------------|
| **Dibuat tahun**      | ~2009 (Bitcoin awal)            | 2000 (RFC 2898)   | 2009                |
| **Tahan GPU?**        | Rendah                           | Rendah-Sedang     | Tinggi (memory-hard)|
| **Tahan ASIC?**       | Tidak                            | Tidak             | Ya                  |
| **Kompleksitas impl.**| Sangat sederhana                | Sedang            | Kompleks            |
| **Parameter**         | iterations saja                 | iter, keyLen      | N, r, p, keyLen     |
| **Digunakan Bitcoin** | wallet.dat enkripsi             | BIP39 seed        | Litecoin mining     |
| **Output size**       | 64 byte tetap                   | Variable          | Variable            |
| **Standar modern?**   | Tidak (sudah usang)             | Diterima          | Sangat dianjurkan   |

**Kesimpulan:** SHA-512 iteratif yang dipakai Bitcoin Core adalah warisan desain awal (2009). Untuk sistem baru, PBKDF2 atau Argon2 (pemenang Password Hashing Competition 2015) lebih dianjurkan.

---

## 12. Keamanan & Etika Penggunaan

### ✅ Penggunaan yang Diizinkan

- Memverifikasi password wallet milik sendiri yang lupa
- Penelitian keamanan dengan izin tertulis dari pemilik
- Pembelajaran dan edukasi kriptografi
- Forensik digital dengan surat perintah resmi

### ❌ Penggunaan yang Dilarang

- Mencoba mengakses wallet orang lain tanpa izin
- Brute-force terhadap wallet yang bukan milikmu
- Segala bentuk pencurian aset digital

### 🔒 Privasi Tool Ini

Tool ini **100% client-side**. Seluruh komputasi terjadi di browser pengguna. Tidak ada data (hash, password, hasil) yang dikirimkan ke server manapun. Kamu bisa memverifikasi ini dengan memeriksa source code dan memantau network traffic di browser DevTools.

---

## 13. Referensi & Bacaan Lanjutan

| Sumber | Keterangan |
|--------|-----------|
| `src/wallet/crypter.cpp` (Bitcoin Core) | Implementasi asli KDF dan enkripsi wallet |
| RFC 2898 | Spesifikasi PBKDF2 |
| FIPS 197 | Spesifikasi AES |
| RFC 2315 | Spesifikasi PKCS7 padding |
| `bitcoin2john.py` (John the Ripper) | Tool untuk mengekstrak hash dari wallet.dat |
| Hashcat mode 11300 | Dokumentasi format hash Bitcoin wallet |

### Topik Lanjutan untuk Dipelajari

- **BIP32/BIP39**: Hierarchical Deterministic Wallets dan mnemonic seed phrase
- **BIP38**: Enkripsi private key dengan scrypt (berbeda dari wallet.dat!)
- **Argon2**: KDF modern pemenang Password Hashing Competition 2015
- **Hardware Security Module (HSM)**: Penyimpanan kunci kriptografi tingkat enterprise

---

## Penutup

Tool dan dokumentasi ini dibuat dengan tujuan **edukasi** — untuk membantu pelajar dan profesional memahami bagaimana sistem kriptografi nyata bekerja di balik dompet Bitcoin. Memahami bug-bug yang ada dalam implementasi yang salah mengajarkan kita bahwa kriptografi yang "hampir benar" sama berbahayanya dengan tidak menggunakan kriptografi sama sekali.

Selamat belajar! 🚀

---

## DONASI

Jika tool ini bermanfaat untuk edukasi dan pembelajaran Anda, donasi sangat dihargai:

**Bitcoin (BTC):** `bc1qn6t8hy8memjfzp4y3sh6fvadjdtqj64vfvlx58`

**Ethereum (ETH):** `0x512936ca43829C8f71017aE47460820Fe703CAea`

**PayPal:** `syabiz@yandex.com`

Donasi akan digunakan untuk pengembangan fitur baru, maintenance server, dan dokumentasi.

---

## KONTAK

- **GitHub Issues:** https://github.com/username/bitcoin-legacy-recovery/issues
- **Email:** syabiz@yandex.com
- **Twitter:** @syabiz

---

## UCAPAN TERIMA KASIH

- **Komunitas Bitcoin** — Untuk dokumentasi dan spesifikasi teknis
- **Pengembang ecdsa** — Library kriptografi yang luar biasa
- **Pengembang base58** — Encoding/decoding yang efisien
- **Semua kontributor** — Yang membantu meningkatkan tool ini
- **Para pengguna** — Untuk feedback dan saran berharga
- **Para Donator** - Biaya Pengembangan, Tagihan Internet dan Waktu

---

Terima kasih telah menggunakan Bitcoin Legacy Address Recovery Tool! 🚀

*Dibuat dengan ❤️ untuk edukasi dan pembelajaran Bitcoin*

*Terakhir diperbarui: 19 Februari 2026*

---

*Dibuat untuk keperluan edukasi internal. Harap digunakan secara bertanggung jawab.*

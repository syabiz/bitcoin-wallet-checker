# 📘 README — Bitcoin wallet.dat Password Checker

> **Internal Educational Material** · English  
> For: cryptography students, digital forensics teams, blockchain developers

---

## 📋 Table of Contents

1. [What Is This Tool?](#1-what-is-this-tool)
2. [Available Files](#2-available-files)
3. [Changelog — Version History](#3-changelog--version-history)
4. [Background: How Does Bitcoin Core Store Passwords?](#4-background-how-does-bitcoin-core-store-passwords)
5. [HashCat Hash Format ($bitcoin$)](#5-hashcat-hash-format-bitcoin)
6. [Verification Workflow — Step by Step](#6-verification-workflow--step-by-step)
7. [KDF: SHA-512 Iterative (The Heart of Everything)](#7-kdf-sha-512-iterative-the-heart-of-everything)
8. [AES-256-CBC Encryption](#8-aes-256-cbc-encryption)
9. [PKCS7 Padding Validation](#9-pkcs7-padding-validation)
10. [Bugs Found & Fixed (All Versions)](#10-bugs-found--fixed-all-versions)
11. [How to Extract a Hash from wallet.dat](#11-how-to-extract-a-hash-from-walletdat)
12. [Code Walkthrough — Function by Function](#12-code-walkthrough--function-by-function)
13. [Comparison: SHA-512 Iterative vs PBKDF2 vs scrypt](#13-comparison-sha-512-iterative-vs-pbkdf2-vs-scrypt)
14. [Security & Ethical Use](#14-security--ethical-use)
15. [References & Further Reading](#15-references--further-reading)

---

## 1. What Is This Tool?

This tool is a **password verifier** for `wallet.dat` files used by Bitcoin Core and Litecoin Core. It runs entirely in the **browser** (client-side) — no data is ever sent to any server.

**Core function:**
Accepts a hash in HashCat format (`$bitcoin$...`) and a password, then verifies whether the password is correct or not — without needing access to the original `wallet.dat` file.

**Who uses it?**
- Wallet owners who forgot their password and want to verify candidate passwords
- Digital forensics teams
- Security researchers studying Bitcoin wallet cryptography
- Students who want to understand how wallet encryption works

---

## 2. Available Files

| File | Language | Description |
|------|----------|-------------|
| `bitcoin-wallet-checker.html` | 🇮🇩 Indonesian | Single checker v1 — verify one hash + one password |
| `bitcoin-batch-checker.html` | 🇮🇩 Indonesian | Batch checker v2 — 100+ hashes with wordlist |
| `bitcoin-batch-checker-en.html` | 🇬🇧 English | Batch checker v2 — English version |
| `README-ID.md` | 🇮🇩 Indonesian | Indonesian documentation |
| `README-EN.md` | 🇬🇧 English | This file |

---

## 3. Changelog — Version History

### 🔖 v1.0 — Single Hash Checker
**File:** `bitcoin-wallet-checker.html`  
**Status:** Stable — Bug-fixed

#### Features in v1.0
- Input one hash (`$bitcoin$` or `$litecoin$`) + one password
- Toggle show/hide password button
- Debug info display (key, IV, ciphertext, decrypted result, padding)
- Hash format validation with descriptive error messages
- 100% client-side, no server requests

#### Bugs Found & Fixed in v1.0

**🐛 Bug #1 — Helper functions not implemented** *(Severity: Critical)*
```
Initial state:
  function hexToBytes(hex) { /* ... */ }       // empty!
  function bytesToHex(bytes) { /* ... */ }     // empty!
  function uint8ToWordArray(u8) { /* ... */ }  // empty!
  function wordArrayToUint8(wa) { /* ... */ }  // empty!

Impact: Tool crashed immediately on first run.
Fix: Full implementation of all conversion functions.
```

**🐛 Bug #2 — mkHexLen misinterpreted (multiplied by 2)** *(Severity: Critical)*
```
Initial state:
  if (masterKeyHex.length !== mkLen * 2)  // ← the *2 is WRONG

Example: hash $bitcoin$64$... → mkLen = 64
  Old code expected: 64 * 2 = 128 hex chars
  Reality: mkHex is only 64 chars → always ERROR!

Explanation: mkHexLen is the length of the HEX STRING, not byte count.
  64 hex chars = 32 bytes (not 64 bytes)

Fix: if (masterKeyHex.length !== mkHexLen)  // no *2
```

**🐛 Bug #3 — Wrong KDF used: scrypt instead of SHA-512** *(Severity: Critical)*
```
Initial state:
  const derivedBytes = await scrypt.scrypt(
      new TextEncoder().encode(password),
      saltBytes, N, r, p, dkLen          // ← scrypt! WRONG
  );

Bitcoin Core does NOT use scrypt for wallet.dat encryption.
Bitcoin Core uses iterative SHA-512 (crypter.cpp).

Impact: Tool always returned "Wrong Password" even when the
        password was 100% correct.

Fix: Implement the correct SHA-512 iterative KDF:
  hash = SHA512(password + salt)   ← round 1
  hash = SHA512(hash)              ← rounds 2..N
  key = hash[0..31], iv = hash[32..47]
```

**🐛 Bug #4 — XOR-based validation had no technical basis** *(Severity: High)*
```
Initial state:
  // XOR decrypted result with wallet IV
  xorResult[i] = decryptedBytes[i] ^ masterKeyBytes[i];
  // Check if all bytes = 0x10
  isValid = xorResult.every(b => b === 0x10);

This logic had absolutely no cryptographic basis.

Fix: Use standard PKCS7 validation (see Bug #5 for further
     refinement in v1.1).
```

---

### 🔖 v1.1 — Single Hash Checker (Hotfix)
**File:** `bitcoin-wallet-checker.html` *(in-place update)*  
**Status:** Stable — Hotfix after real-world testing

#### Background for v1.1

After v1.0 was released, real-world testing with a hash from a zero-balance wallet discovered a **false positive** — the tool reported the password as correct when Bitcoin Core itself rejected it.

Test hash: `$bitcoin$64$ff4eb1d0...$16$6b8207637fc796a0$37698$2$00$2$00`  
Test password: `"2315"` → v1.0 said **CORRECT** ❌ (should have been **WRONG**)

**🐛 Bug #5 — PKCS7 False Positive: Padding `0x01` Always Passes** *(Severity: High)*
```
State in v1.0 (after fixing Bug #4):
  const last = decryptedBytes[decryptedBytes.length - 1];
  let isValid = (last >= 1 && last <= 16);  // ← too lenient!

Problem:
  Wrong password → decryption produces random data → last byte = 0x01
  Validation: 0x01 >= 1 && 0x01 <= 16 → TRUE → false positive!

  False positive probability: ~6.25% (1 in 16 chance)
  Meaning: ~1 in 16 wrong passwords will be reported as CORRECT.

Root cause:
  Bitcoin Core master key is ALWAYS 32 bytes (AES-256).
  PKCS7 on 32 bytes of data → padding = one full block = 16 × 0x10
  Hashcat takes the last 2 blocks (32 bytes) → final block = all 0x10

Fix — Bitcoin-specific strict validation:
  let isValid = (last === 0x10);  // must be exactly 0x10
  if (isValid) {
      for (let i = decBytes.length - 16; i < decBytes.length; i++) {
          if (decBytes[i] !== 0x10) { isValid = false; break; }
      }
  }

  False positive probability after fix: ~1/(256^16) ≈ zero
```

---

### 🔖 v2.0 — Batch Checker (Major Release)
**File:** `bitcoin-batch-checker.html` / `bitcoin-batch-checker-en.html`  
**Status:** Stable — Current

#### New Features in v2.0

**⚡ Batch Checker Tab**
- Input a list of hashes (100+ at once), one per line
- Input a password wordlist, one per line
- Upload `.txt` wordlist file directly from the browser
- Real-time progress bar with full statistics:
  - Found / checked / remaining counts
  - Speed (hashes/minute)
  - Estimated time to completion (ETA)
- Concurrency engine: process 1 / 2 / 4 combinations in parallel
- **Pause** button — suspend without losing progress
- **Stop** button — halt at any time
- Mode: "stop when found" or "try all passwords"
- Live log with timestamps for every activity
- Result table filtering: All / Found / Failed / Error
- Export results to **CSV** (all results or found-only)
- Copy found passwords to clipboard
- Summary cards: total found, failed, total hashes, elapsed time

**🔍 Single Check Tab**
- Verify one hash + one password
- Functionally identical to v1.1
- All bug fixes included

**📖 Guide Tab**
- Inline hash format documentation
- Verification algorithm explanation
- Batch checking tips

**🌐 Available in two languages**
- `bitcoin-batch-checker.html` — Indonesian
- `bitcoin-batch-checker-en.html` — English

#### Technical Improvements in v2.0

| Aspect | v1.x | v2.0 |
|--------|-------|-------|
| Hashes per run | 1 | 1 — 1000+ |
| Passwords per run | 1 | 1 — unlimited |
| Concurrency | — | 1 / 2 / 4 parallel |
| Progress tracking | — | Real-time with ETA |
| Export results | — | CSV + clipboard |
| Pause / Stop | — | ✓ |
| Live log | — | ✓ (500-line buffer) |
| Upload wordlist | — | ✓ (.txt) |
| Language | Indonesian | Indonesian + English |
| Crypto engine | SHA-512 + AES + strict PKCS7 | Inherited — unchanged |

#### Crypto Engine Unchanged

> All cryptographic logic (SHA-512 iterative KDF, AES-256-CBC, strict `0x10×16` padding validation) is identical between v1.1 and v2.0. No new crypto bugs were introduced or discovered.

---

## 4. Background: How Does Bitcoin Core Store Passwords?

When you encrypt a wallet in Bitcoin Core, the program does not directly encrypt the private key with your password. There are multiple layers:

```
┌─────────────────────────────────────────────────────────────┐
│                  WALLET ENCRYPTION ARCHITECTURE              │
│                                                             │
│  PASSWORD (plaintext from user)                             │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  KDF: SHA-512 Iterative + Salt (N iterations)       │   │
│  │  → Produces: Key (32 bytes) + IV (16 bytes)         │   │
│  └─────────────────────────────────────────────────────┘   │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  AES-256-CBC Decrypt on Encrypted Master Key        │   │
│  └─────────────────────────────────────────────────────┘   │
│       │                                                     │
│       ▼                                                     │
│  Master Key (plaintext) → used to encrypt                   │
│  all Private Keys inside the wallet                         │
└─────────────────────────────────────────────────────────────┘
```

**Key Concepts:**
- **Master Key** — The primary secret key used to encrypt all private keys. This master key is itself encrypted using the user's password.
- **Salt** — Random data added before hashing. Prevents rainbow table attacks.
- **Iterations (N)** — How many times SHA-512 is repeated. Higher N = slower brute-force.
- **IV (Initialization Vector)** — Starting value for CBC mode. Derived from KDF, not stored separately.

---

## 5. HashCat Hash Format ($bitcoin$)

The hash is produced by `bitcoin2john.py` (from the John the Ripper package) reading `wallet.dat`.

### Format Structure

```
$bitcoin$<mkHexLen>$<mkHex>$<saltHexLen>$<saltHex>$<iterations>$<f1>$<f2>$<f3>$<f4>
```

### Field Reference Table

| Position | Field Name    | Type    | Description |
|----------|--------------|---------|-------------|
| [0]      | `mkHexLen`   | integer | **Length of the HEX STRING** for masterKey — not byte count! |
| [1]      | `mkHex`      | hex     | Encrypted Master Key in hex |
| [2]      | `saltHexLen` | integer | **Length of the HEX STRING** for salt — not byte count! |
| [3]      | `saltHex`    | hex     | Salt in hex |
| [4]      | `iterations` | integer | Number of SHA-512 iterations |
| [5..8]   | (extra)      | —       | Extra fields, not used in verification |

### Real Hash Example

```
$bitcoin$64$617c4b22fabd578e0f4d030245a0cbebd9da426fbee49c2feb885fa190b65096$16$dff2b89e4d885c28$35714$2$00$2$00
```

Broken down:
```
Prefix      : $bitcoin$
mkHexLen    : 64   → mkHex is 64 hex chars long = 32 bytes
mkHex       : 617c4b22fabd578e0f4d030245a0cbebd9da426fbee49c2feb885fa190b65096
saltHexLen  : 16   → saltHex is 16 hex chars long = 8 bytes
saltHex     : dff2b89e4d885c28
iterations  : 35714
```

### ⚠️ Common Pitfall — mkHexLen Is NOT a Byte Count!

```
WRONG ❌:  expected_length = mkHexLen * 2
           → 64 * 2 = 128 hex chars (incorrect!)

CORRECT ✅:  expected_length = mkHexLen
             → 64 hex chars (correct!)
```

`mkHexLen` is the number of **hex characters**, not bytes. Since 1 byte = 2 hex chars, `mkHexLen=64` means 64 hex chars = 32 bytes.

---

## 6. Verification Workflow — Step by Step

```
INPUT: hash ($bitcoin$...) + password (text)
           │
           ▼
┌──────────────────────────┐
│  STEP 1: Parse Hash      │
│  Extract mkHex, saltHex, │
│  iterations              │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  STEP 2: KDF             │
│  SHA-512 Iterative       │
│  Input: password + salt  │
│  Repeat N times          │
│  Output: 64 bytes        │
│  key = bytes[0..31]      │
│  iv  = bytes[32..47]     │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  STEP 3: AES Decrypt     │
│  AES-256-CBC             │
│  Key = 32 bytes from KDF │
│  IV  = 16 bytes from KDF │
│  Data = mkHex[0..31]     │
│  Output: 32 bytes        │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  STEP 4: Check Padding   │
│  Last 16 bytes           │
│  must all equal 0x10?    │
└──────────┬───────────────┘
           │
     ┌─────┴──────┐
     ▼            ▼
  YES ✅        NO ❌
"Password    "Wrong
  Correct!"   Password!"
```

---

## 7. KDF: SHA-512 Iterative (The Heart of Everything)

KDF = **Key Derivation Function** — a function for deriving a cryptographic key from a plaintext password.

### Bitcoin Core Algorithm (crypter.cpp)

```
ROUND 1:
  data = bytes(password) + bytes(salt)
  hash = SHA-512(data)              ← 64 bytes

ROUNDS 2 through N:
  hash = SHA-512(hash)              ← previous hash only!

FINAL OUTPUT (64 bytes):
  key = hash[0..31]                 ← 32 bytes for AES-256
  iv  = hash[32..47]                ← 16 bytes for AES CBC
```

### JavaScript Implementation

```javascript
async function deriveKeyBitcoinSHA512(password, saltBytes, iterations) {
    const passBytes = new TextEncoder().encode(password);

    // Combine password + salt
    const combined = new Uint8Array(passBytes.length + saltBytes.length);
    combined.set(passBytes, 0);
    combined.set(saltBytes, passBytes.length);

    // Round 1: SHA-512(password + salt)
    let hashBuf = await crypto.subtle.digest('SHA-512', combined);

    // Rounds 2..N: SHA-512(previous hash only)
    for (let i = 1; i < iterations; i++) {
        hashBuf = await crypto.subtle.digest('SHA-512', hashBuf);
    }

    return new Uint8Array(hashBuf); // 64 bytes
}
```

### Iteration Visualization

```
Iteration   Input                          Output
─────────── ────────────────────────────── ──────────────────
1           SHA-512(password + salt)    →  hash₁  (64 bytes)
2           SHA-512(hash₁)              →  hash₂  (64 bytes)
3           SHA-512(hash₂)              →  hash₃  (64 bytes)
...         ...                            ...
N           SHA-512(hash_{N-1})         →  hashₙ  (64 bytes)

key = hashₙ[0..31]   (32 bytes)
iv  = hashₙ[32..47]  (16 bytes)
```

### Why Are Iterations Necessary?

Without iterations, an attacker can try millions of passwords per second on a GPU. With `iterations = 35714`, each attempt requires 35,714 SHA-512 computations — making brute-force dramatically slower.

> **Analogy:** Like locking a door with 35,714 locks that must each be opened one at a time, in sequence.

---

## 8. AES-256-CBC Encryption

### AES (Advanced Encryption Standard)

AES is the industry-standard symmetric encryption algorithm. Symmetric means the same key is used for both encryption and decryption.

- **AES-256**: 256-bit key (32 bytes)
- **CBC (Cipher Block Chaining)**: An operating mode that chains data blocks together

### How CBC Works

```
ENCRYPTION:
  P₁  XOR  IV  → AES(key) → C₁
  P₂  XOR  C₁  → AES(key) → C₂
  P₃  XOR  C₂  → AES(key) → C₃

DECRYPTION:
  AES_dec(key, C₁)  XOR  IV  → P₁
  AES_dec(key, C₂)  XOR  C₁  → P₂
  AES_dec(key, C₃)  XOR  C₂  → P₃
```

### Why Is IV Important?

The IV ensures that the same plaintext produces different ciphertext each time it's encrypted (as long as the IV differs). In Bitcoin Core, the IV is not stored separately — it is regenerated from the KDF whenever needed.

---

## 9. PKCS7 Padding Validation

### Why Is Padding Needed?

AES-CBC works on 16-byte blocks. If the data is not a multiple of 16, padding is added.

### PKCS7 Scheme

```
Data is short N bytes from a multiple of 16 → append N bytes each valued N

Example (3 bytes short):
  [original data...]  03 03 03

Bitcoin case (32-byte data = multiple of 16 → full block padding):
  [32 bytes of data]  10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
                      ↑ 0x10 = 16 decimal, repeated 16 times
```

### Strict Bitcoin Validation

```javascript
// ❌ LENIENT VALIDATION — vulnerable to false positives (~6.25%):
const last = decryptedBytes[decryptedBytes.length - 1];
let isValid = (last >= 1 && last <= 16);  // 0x01 always passes!

// ✅ STRICT VALIDATION — Bitcoin-specific (false positive ~0):
let isValid = (last === 0x10);  // must be exactly 0x10
if (isValid) {
    for (let i = decryptedBytes.length - 16; i < decryptedBytes.length; i++) {
        if (decryptedBytes[i] !== 0x10) { isValid = false; break; }
    }
}
```

**Why must it be exactly `0x10`?** Because the Bitcoin master key is always 32 bytes (AES-256), and PKCS7 on 32 bytes of data produces exactly one full block of padding = 16 × `0x10`.

---

## 10. Bugs Found & Fixed (All Versions)

Summary of all bugs from v1.0 through v1.1:

| # | Bug | Severity | Found in | Fixed in | Status |
|---|-----|----------|----------|----------|--------|
| 1 | Helper functions not implemented | Critical | v1.0 initial | v1.0 | ✅ Fixed |
| 2 | `mkHexLen` multiplied by 2 — wrong interpretation | Critical | v1.0 initial | v1.0 | ✅ Fixed |
| 3 | Wrong KDF: scrypt used instead of SHA-512 | Critical | v1.0 initial | v1.0 | ✅ Fixed |
| 4 | XOR-based validation had no technical basis | High | v1.0 initial | v1.0 | ✅ Fixed |
| 5 | PKCS7 false positive: `0x01` padding always passes | High | v1.0 (real-world testing) | v1.1 | ✅ Fixed |

Full details for each bug are in the [Changelog](#3-changelog--version-history).

---

## 11. How to Extract a Hash from wallet.dat

### Using bitcoin2john.py

```bash
# Install dependency
pip install bsddb3

# Extract hash
python bitcoin2john.py /path/to/wallet.dat
```

Output:
```
wallet.dat:$bitcoin$64$xxxxx$16$xxxxx$25000$2$00$2$00
```

The portion after `:` is the hash to paste into this tool.

### Using hashcat (Educational Reference)

```bash
# Mode -m 11300 = Bitcoin/Litecoin wallet.dat
hashcat -m 11300 hash.txt wordlist.txt

# With rules
hashcat -m 11300 hash.txt wordlist.txt -r rules/best64.rule
```

> **Important:** Use only on your own wallet or with official written permission.

---

## 12. Code Walkthrough — Function by Function

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
CryptoJS uses an internal `WordArray` format (array of 32-bit integers, big-endian). This function converts a standard `Uint8Array` to that format.

```javascript
function uint8ToWordArray(u8) {
    const words = [];
    for (let i = 0; i < u8.length; i += 4)
        words.push(
            ((u8[i]   || 0) << 24) |  // byte 1 → bits 31-24
            ((u8[i+1] || 0) << 16) |  // byte 2 → bits 23-16
            ((u8[i+2] || 0) <<  8) |  // byte 3 → bits 15-8
            ((u8[i+3] || 0))          // byte 4 → bits 7-0
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
    const masterKey  = parts[1];            // 64-char hex string
    const saltHexLen = parseInt(parts[2]);  // 16
    const saltHex    = parts[3];            // 16-char hex string
    const iterations = parseInt(parts[4]);  // 35714

    // KEY INSIGHT: validate directly, without *2
    if (masterKey.length !== mkHexLen) throw new Error("...");
    return { masterKeyHex: masterKey, saltHex, iterations };
}
```

### `deriveKeyBitcoinSHA512(password, saltBytes, iterations)`
```javascript
async function deriveKeyBitcoinSHA512(password, saltBytes, iterations) {
    const passBytes = new TextEncoder().encode(password);

    // Combine password + salt
    const combined = new Uint8Array(passBytes.length + saltBytes.length);
    combined.set(passBytes, 0);
    combined.set(saltBytes, passBytes.length);

    // Round 1: SHA-512(password + salt)
    let hashBuf = await crypto.subtle.digest('SHA-512', combined);

    // Rounds 2..N: SHA-512(hash only)
    for (let i = 1; i < iterations; i++)
        hashBuf = await crypto.subtle.digest('SHA-512', hashBuf);

    // key = [0..31], iv = [32..47]
    return new Uint8Array(hashBuf);
}
```

---

## 13. Comparison: SHA-512 Iterative vs PBKDF2 vs scrypt

| Criterion | SHA-512 Iterative | PBKDF2-SHA512 | scrypt |
|-----------|------------------|---------------|--------|
| **Introduced** | ~2009 | 2000 (RFC 2898) | 2009 |
| **GPU resistant?** | Low | Low-Medium | High (memory-hard) |
| **ASIC resistant?** | No | No | Yes |
| **Complexity** | Very simple | Medium | Complex |
| **Parameters** | iterations only | iter, keyLen | N, r, p, keyLen |
| **Used in Bitcoin** | wallet.dat encryption | BIP39 seed | Litecoin mining |
| **Output size** | Fixed 64 bytes | Variable | Variable |
| **Modern standard?** | No (legacy) | Accepted | Highly recommended |

**Conclusion:** The SHA-512 iterative KDF used by Bitcoin Core is a legacy design choice from 2009. For new systems, use PBKDF2 or **Argon2** (winner of the Password Hashing Competition 2015).

---

## 14. Security & Ethical Use

### ✅ Permitted Use
- Verifying the password of your own wallet
- Security research with written permission from the wallet owner
- Cryptography education and learning
- Digital forensics under official legal authority

### ❌ Prohibited Use
- Accessing another person's wallet without permission
- Brute-forcing wallets you do not own
- Any form of digital asset theft

### 🔒 Privacy of This Tool

This tool is **100% client-side**. All computation happens in your browser. No data (hashes, passwords, results) is ever sent to any server. You can verify this by monitoring the Network tab in your browser's DevTools.

---

## 15. References & Further Reading

| Source | Description |
|--------|-------------|
| `src/wallet/crypter.cpp` (Bitcoin Core) | Original KDF and wallet encryption implementation |
| RFC 2898 | PBKDF2 specification |
| FIPS 197 | AES specification |
| RFC 2315 | PKCS7 padding specification |
| `bitcoin2john.py` (John the Ripper) | Tool to extract hashes from wallet.dat |
| Hashcat mode 11300 | Bitcoin wallet hash format documentation |

### Further Topics to Explore

- **BIP32/BIP39** — Hierarchical Deterministic Wallets and mnemonic seed phrases
- **BIP38** — Private key encryption with scrypt (different from wallet.dat!)
- **Argon2** — Modern KDF, winner of the Password Hashing Competition 2015
- **HSM (Hardware Security Module)** — Enterprise-grade cryptographic key storage

---

## Closing

This tool and documentation were created for **educational purposes** — to help students and professionals understand how real cryptographic systems work inside Bitcoin wallets. Understanding the bugs in incorrect implementations teaches us that "almost correct" cryptography is just as dangerous as no cryptography at all.

Happy learning! 🚀

---

## Donation

### If this tool has been useful for your education and learning, donations are greatly appreciated:

- **Bitcoin (BTC)** — bc1qn6t8hy8memjfzp4y3sh6fvadjdtqj64vfvlx58
- **Ethereum (ETH)** — 0x512936ca43829C8f71017aE47460820Fe703CAea
- **Solana (SOL)** — 6ZZrRmeGWMZSmBnQFWXG2UJauqbEgZnwb4Ly9vLYr7mi
- **PayPal:** — syabiz@yandex.com

Donations will be used for developing new features, server maintenance, and documentation.

---

## CONTACT

- **GitHub Issues:** https://github.com/syabiz/Bitcoin-Wallet-Checker/issues
- **Email:** syabiz@yandex.com
- **Twitter:** @syabiz

---

Thank you for using the Bitcoin Wallet Checker Tool! 🚀
*Made with ❤️ for Bitcoin education and learning*

*Last updated: February 19, 2026*

---

*Created for internal educational use. Please use responsibly.*

# OTTO Crypt PY — Interop E2EE & Streaming AEAD for Python

**Package:** `otto-crypt-py`  
**License:** MIT  
**Author:** Ivan Doe  
**Python:** 3.9+  
**Interop:** ✅ Compatible with Laravel package `ivansostarko/otto-crypt-php` and Node package `otto-crypt-js` (encrypt in one language ↔ decrypt in another).

OTTO Crypt PY implements the **OTTO-256-GCM-HKDF-SIV** construction: a practical, misuse-resistant design built on **AES-256-GCM** (via `cryptography`), **HKDF(SHA‑256)**, **Argon2id** and **X25519** (via libsodium/PyNaCl). It supports **chunked streaming encryption** for very large files (photos, docs, audio, video) and **end‑to‑end (E2E)** sessions with ephemeral X25519 key exchange.

> ⚠️ **Security notice:** While OTTO uses trusted primitives, the full construction is **custom**. Treat this library as **pre‑audit** and obtain an **independent cryptographic review** before production.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [CLI](#cli)
  - [Python API](#python-api)
- [Algorithm Design](#algorithm-design)
  - [Header](#header)
  - [Chunk Format](#chunk-format)
  - [Key Schedule](#key-schedule)
  - [Nonce Derivation (HKDF‑SIV Style)](#nonce-derivation-hkdf-siv-style)
  - [X25519 E2E Mode](#x25519-e2e-mode)
- [Interoperability](#interoperability)
- [Configuration & Defaults](#configuration--defaults)
- [API Reference](#api-reference)
- [Docker](#docker)
- [Comparison](#comparison)
- [Security Considerations](#security-considerations)
- [Performance Notes](#performance-notes)
- [Examples](#examples)
- [Roadmap](#roadmap)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)
- [Responsible Disclosure](#responsible-disclosure)

---

## Features

- **AES‑256‑GCM AEAD** (16‑byte tags) using `cryptography`.
- **Deterministic per‑chunk nonces** derived by HKDF (SIV‑style) to reduce nonce‑reuse risk.
- **Streaming**: chunked encryption for large files (default **1 MiB** per chunk; configurable).
- **E2E session keys** with **X25519** (ephemeral sender key in header).
- **Password mode** via **Argon2id** (PyNaCl/libsodium `crypto_pwhash`).
- **Raw 32‑byte key** mode for advanced deployments.
- **Full AD binding**: the entire header is used as Associated Data.
- **Byte‑for‑byte compatibility** with Laravel & Node implementations.

---

## Installation

Local editable install:

```bash
pip install -e .   # run inside the otto-crypt-py folder
```

**Requires:** Python 3.9+, [`cryptography`](https://pypi.org/project/cryptography/), [`PyNaCl`](https://pypi.org/project/PyNaCl/).

---

## Quick Start

### CLI

The repository includes a tiny CLI named `otto`:

```bash
# Encrypt with password
./otto encrypt input.bin output.bin.otto --password "P@ssw0rd!"

# Decrypt with password
./otto decrypt output.bin.otto output.dec.bin --password "P@ssw0rd!"

# E2E: encrypt to recipient X25519 public key (base64/hex/raw)
./otto encrypt photo.jpg photo.jpg.otto --recipient "<BASE64_OR_HEX_PUBLIC>"

# E2E: decrypt with your X25519 secret key (base64/hex/raw)
./otto decrypt photo.jpg.otto photo.jpg --sender-secret "<BASE64_OR_HEX_SECRET>"

# Raw key (32 bytes)
./otto encrypt doc.pdf doc.pdf.otto --raw-key "abcdef..."
```

### Python API

```python
from otto_crypt import OttoCrypt, KeyExchange

o = OttoCrypt()  # default chunk_size=1MiB; Argon2id MODERATE params

# 1) Strings (single-shot)
cipher, header = o.encrypt_string(b"Hello OTTO", options={"password": "P@ssw0rd!"})
plain = o.decrypt_string(cipher, header, options={"password": "P@ssw0rd!"})
print(plain.decode())  # Hello OTTO

# 2) Files (streaming)
o.encrypt_file("in.mp4", "in.mp4.otto", options={"password": "P@ssw0rd!"})
o.decrypt_file("in.mp4.otto", "in.dec.mp4", options={"password": "P@ssw0rd!"})

# 3) X25519 E2E
kp = KeyExchange.generate_keypair()
o.encrypt_file("movie.mov", "movie.mov.otto", options={"recipient_public": kp["public"].hex()})
o.decrypt_file("movie.mov.otto", "movie.mov", options={"sender_secret": kp["secret"].hex()})
```

---

## Algorithm Design

### Header

Binary header = fixed part + variable part (HVAR):

```
magic      : "OTTO1" (5 bytes)
algo_id    : 0xA1            # AES-256-GCM + HKDF-SIV nonces
kdf_id     : 0x01=password | 0x02=raw key | 0x03=X25519
flags      : bit0=chunked
reserved   : 0x00
header_len : uint16 BE length of HVAR
HVAR:
  file_salt  (16)
  if kdf=01 (password): pw_salt(16) + opslimit(uint32 BE) + memlimitKiB(uint32 BE)
  if kdf=03 (X25519):   eph_pubkey(32)
```

**Associated Data (AD)** for every AEAD operation is the full header (`fixed || HVAR`).

### Chunk Format

Per chunk:
```
chunk_len : uint32 BE length of ciphertext (not including tag)
cipher    : N bytes
tag       : 16 bytes (GCM tag)
```

### Key Schedule

Let `master_key` originate from **Argon2id**, **raw key**, or **X25519 ECDH**:

```
enc_key   = HKDF(master_key, len=32, info="OTTO-ENC-KEY",  salt=file_salt)
nonce_key = HKDF(master_key, len=32, info="OTTO-NONCE-KEY", salt=file_salt)
```

### Nonce Derivation (HKDF‑SIV Style)

Per‑chunk deterministic nonce:
```
nonce_i = HKDF(nonce_key, len=12, info="OTTO-CHUNK-NONCE" || counter64be, salt="")
```
This avoids the class of catastrophic mistakes around GCM nonce reuse.

### X25519 E2E Mode

- **Sender:** generates an **ephemeral** X25519 keypair per session, puts `eph_pubkey` in header:
  - `shared = scalarmult(eph_sk, recipient_pk)`  
  - `master_key = HKDF(shared, len=32, info="OTTO-E2E-MASTER", salt=file_salt)`
- **Recipient:** uses their **long‑term secret key** with `eph_pubkey` to derive the same `master_key`.  
- Provides **forward secrecy** for sessions when ephemeral secrets are erased after use.

---

## Interoperability

This Python package is **byte‑for‑byte compatible** with the Laravel and Node implementations:

- **Header fields** and order are identical.
- **KDFs & parameters** (Argon2id ops/mem in header) match.
- **HKDF contexts/labels** and **AD** usage are identical.
- **Per‑chunk nonce derivation** is the same.
- **Streaming layout** is the same.

You can encrypt a string/file in PHP and decrypt it here in Python (and vice‑versa).

---

## Configuration & Defaults

```python
OttoCrypt(
  chunk_size=1024*1024,   # 1 MiB
  opslimit=None,          # uses libsodium MODERATE by default
  memlimit=None           # uses libsodium MODERATE by default
)
```

- **Argon2id** defaults to libsodium’s `OPSLIMIT_MODERATE` / `MEMLIMIT_MODERATE`. Override if needed for your environment.
- **Chunk size**: tune for throughput vs memory footprint (1–8 MiB typical).

---

## API Reference

### `class OttoCrypt`

- `encrypt_string(plaintext: bytes, options: dict) -> (cipher_and_tag: bytes, header: bytes)`  
  Options: one of `{"password": str}`, `{"raw_key": bytes|hex|b64|str}`, `{"recipient_public": bytes|hex|b64|str}`.

- `decrypt_string(cipher_and_tag: bytes, header: bytes, options: dict) -> plaintext: bytes`  
  Options: one of `{"password": str}`, `{"raw_key": ...}`, `{"sender_secret": ...}`.

- `encrypt_file(in_path: str, out_path: str, options: dict) -> None`

- `decrypt_file(in_path: str, out_path: str, options: dict) -> None`

### `class KeyExchange`

- `generate_keypair() -> {"secret": bytes, "public": bytes}`
- `derive_shared_secret(my_secret: bytes, their_public: bytes) -> bytes`
- `derive_session_key(shared_secret: bytes, salt: bytes=b"", context: str="OTTO-X25519-SESSION") -> bytes`

---

## Docker

A **Dockerfile** and **docker-compose.yml** are provided to run the CLI/API without local Python setup.

```bash
docker compose up -d --build
docker compose run --rm setup
docker compose run --rm app otto encrypt /data/in.bin /data/in.bin.otto --password "x"
docker compose run --rm app otto decrypt /data/in.bin.otto /data/in.dec.bin --password "x"
```

See `ops-DOCKER-README.md` for details.

---

## Comparison

| Scheme | AEAD | Nonce Strategy | Streaming | E2E | Notes |
|---|---|---|---|---|---|
| **OTTO‑256‑GCM‑HKDF‑SIV** | AES‑256‑GCM | **Deterministic HKDF per chunk** | **Yes** | **X25519** | Custom composition; audit advised |
| AES‑GCM (typical) | AES‑GCM | Random/monotonic (app‑managed) | App‑defined | App‑defined | Easy to misuse via nonce reuse |
| AES‑SIV (RFC 5297) | SIV | Deterministic | App‑defined | App‑defined | Standard MR; slower than GCM |
| ChaCha20‑Poly1305 | ChaCha20/Poly1305 | App‑managed | App‑defined | App‑defined | Great on non‑AES‑NI CPUs |
| libsodium secretstream | XChaCha20‑Poly1305 | Internal | **Yes** | App‑defined | Excellent, battle‑tested streaming API |

Pick OTTO if you need **AES‑GCM**, **deterministic nonces** for safer streaming, and **built‑in X25519 E2E**, with **Laravel/Node/Python** interop.

---

## Security Considerations

- Provides **confidentiality + integrity** via AEAD (GCM).
- Deterministic nonces help avoid app‑level nonce reuse errors.
- **Password security** depends on your Argon2id parameters and chosen password; prefer **E2E keys** for messengers.
- **Forward secrecy**: ensured per session with ephemeral sender keys if erased after use.
- **Endpoint compromise** is out of scope.
- **Side‑channels**: relies on `cryptography` + libsodium; no extra constant‑time guarantees beyond those libs.
- **Key erasure**: best effort (Python immutability means some copies may remain in memory/GC).
- **Audit**: recommended before production rollout.

---

## Performance Notes

- AES‑GCM uses OpenSSL via `cryptography` (leverages AES‑NI when available).
- Argon2id dominates setup time; streaming is dominated by disk I/O and AES‑GCM speed.
- Tune `chunk_size` and I/O buffering for your environment.

---

## Examples

### Encrypt in Laravel → Decrypt in Python (password)

1) **Laravel**:
```php
[$cipher, $header] = Otto::encryptString("hello", options: ['password' => 'x']);
echo base64_encode($cipher), "\n";
echo base64_encode($header), "\n";
```

2) **Python**:
```python
from base64 import b64decode
from otto_crypt import OttoCrypt
o = OttoCrypt()
cipher = b64decode(CIPHER_B64)
header = b64decode(HEADER_B64)
plain = o.decrypt_string(cipher, header, options={"password": "x"})
print(plain.decode())  # hello
```

### Encrypt in Python → Decrypt in Node (X25519)

1) **Python**:
```python
from otto_crypt import OttoCrypt
o = OttoCrypt()
o.encrypt_file("photo.jpg", "photo.jpg.otto", options={"recipient_public": RECIPIENT_PK_BASE64})
```

2) **Node**:
```js
await otto.decryptFile("photo.jpg.otto", "photo.jpg", { sender_secret: MY_SECRET_BASE64 });
```

---

## Roadmap

- Cross‑language test vectors and fixtures.
- Optional **AEAD‑SIV** backend.
- Multi‑recipient envelope encryption.
- PyPI publishing & wheels for common platforms.
- CI: lint, unit tests, interop tests.

---

## FAQ

**Is this FIPS compliant?**  
Depends on your OpenSSL build. The **construction** is custom and not a NIST standard.

**Can I rotate keys?**  
Yes. Re‑encrypt with a new recipient key or password; header binds parameters to ciphertext.

**Why deterministic nonces?**  
To avoid catastrophic GCM nonce reuse in streaming/parallel code.

**Does this replace libsodium secretstream?**  
No. `crypto_secretstream` is excellent. OTTO focuses on AES‑GCM with deterministic nonces and cross‑language interop.

---

## Contributing

PRs welcome! Please include a clear rationale, tests (ideally **cross‑language**), and security notes for crypto changes. Discuss design‑level changes in an issue first.

---

## License

MIT © 2025 Ivan Sostarko

---

## Responsible Disclosure

If you believe you’ve found a vulnerability, **do not open a public issue**.  
Please contact the maintainer privately (see project metadata) with details and reproduction steps.  
We’ll coordinate a fix and responsible disclosure timeline.

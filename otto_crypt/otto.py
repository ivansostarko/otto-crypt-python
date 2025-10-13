import os
import struct
import hmac
import hashlib
from typing import Tuple, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.bindings import (
    crypto_scalarmult_base,
    crypto_scalarmult,
    crypto_pwhash_ALG_ARGON2ID13,
    crypto_pwhash,
    crypto_pwhash_OPSLIMIT_MODERATE,
    crypto_pwhash_MEMLIMIT_MODERATE,
)

MAGIC = b"OTTO1"          # 5 bytes
ALGO_ID = 0xA1            # AES-256-GCM + HKDF-SIV-style nonces
KDF_PASSWORD = 0x01
KDF_RAWKEY   = 0x02
KDF_X25519   = 0x03

FLAG_CHUNKED = 0x01

DEFAULT_CHUNK = 1024 * 1024  # 1 MiB

def _be16(n: int) -> bytes:
    return struct.pack(">H", n & 0xFFFF)

def _be32(n: int) -> bytes:
    return struct.pack(">I", n & 0xFFFFFFFF)

def _read_u32(b: bytes, off: int) -> int:
    return struct.unpack(">I", b[off:off+4])[0]

def _decode_key(txt: Optional[bytes or str]) -> bytes:
    if txt is None:
        return b""
    if isinstance(txt, bytes):
        return txt
    s = txt.strip()
    # hex?
    try:
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
            return bytes.fromhex(s)
    except Exception:
        pass
    # base64?
    import base64, re
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        try:
            b = base64.b64decode(s, validate=True)
            if b:
                return b
        except Exception:
            pass
    # raw utf-8 fallback
    return s.encode("utf-8")

class HKDF:
    @staticmethod
    def derive(ikm: bytes, length: int, info: bytes = b"", salt: bytes = b"", hash_name: str = "sha256") -> bytes:
        prk = HKDF.extract(ikm, salt, hash_name)
        return HKDF.expand(prk, info, length, hash_name)

    @staticmethod
    def extract(ikm: bytes, salt: bytes = b"", hash_name: str = "sha256") -> bytes:
        if salt == b"":
            salt = b"\x00" * hashlib.new(hash_name).digest_size
        return hmac.new(salt, ikm, hash_name).digest()

    @staticmethod
    def expand(prk: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
        hash_len = hashlib.new(hash_name).digest_size
        n = (length + hash_len - 1) // hash_len
        okm = b""
        t = b""
        for i in range(1, n + 1):
            t = hmac.new(prk, t + info + bytes([i]), hash_name).digest()
            okm += t
        return okm[:length]

def _chunk_nonce(nonce_key: bytes, counter: int) -> bytes:
    hi = (counter >> 32) & 0xFFFFFFFF
    lo = counter & 0xFFFFFFFF
    info = b"OTTO-CHUNK-NONCE" + _be32(hi) + _be32(lo)
    return HKDF.derive(nonce_key, 12, info, b"", "sha256")

class KeyExchange:
    @staticmethod
    def generate_keypair() -> Dict[str, bytes]:
        sk = os.urandom(32)  # scalar
        pk = crypto_scalarmult_base(sk)  # 32 bytes
        return {"secret": sk, "public": pk}

    @staticmethod
    def derive_shared_secret(my_secret: bytes, their_public: bytes) -> bytes:
        return crypto_scalarmult(my_secret, their_public)

    @staticmethod
    def derive_session_key(shared_secret: bytes, salt: bytes = b"", context: str = "OTTO-X25519-SESSION") -> bytes:
        return HKDF.derive(shared_secret, 32, context.encode("ascii"), salt, "sha256")

class OttoCrypt:
    def __init__(self, chunk_size: int = DEFAULT_CHUNK, opslimit: Optional[int] = None, memlimit: Optional[int] = None):
        self.chunk_size = int(chunk_size)
        self.opslimit = int(opslimit) if opslimit is not None else crypto_pwhash_OPSLIMIT_MODERATE
        self.memlimit = int(memlimit) if memlimit is not None else crypto_pwhash_MEMLIMIT_MODERATE

    # ===== Strings (single chunk) =====
    def encrypt_string(self, plaintext: bytes, options: Dict) -> Tuple[bytes, bytes]:
        ctx = self._init_context(options, chunked=False)
        enc_key = ctx["enc_key"]
        nonce_key = ctx["nonce_key"]
        ad = ctx["header"]
        nonce = _chunk_nonce(nonce_key, 0)
        aes = AESGCM(enc_key)
        ct = aes.encrypt(nonce, plaintext, ad)  # returns cipher||tag
        # split into cipher + tag (last 16 bytes)
        tag = ct[-16:]
        cipher = ct[:-16]
        return cipher + tag, ctx["header"]

    def decrypt_string(self, cipher_and_tag: bytes, header: bytes, options: Dict) -> bytes:
        ctx = self._init_context_for_decryption(header, options)
        ad = ctx["ad"]
        enc_key = ctx["enc_key"]
        nonce_key = ctx["nonce_key"]
        if len(cipher_and_tag) < 16:
            raise ValueError("ciphertext too short")
        cipher = cipher_and_tag[:-16]
        tag = cipher_and_tag[-16:]
        nonce = _chunk_nonce(nonce_key, 0)
        aes = AESGCM(enc_key)
        return aes.decrypt(nonce, cipher + tag, ad)

    # ===== Files (streaming) =====
    def encrypt_file(self, in_path: str, out_path: str, options: Dict) -> None:
        ctx = self._init_context(options, chunked=True)
        enc_key = ctx["enc_key"]
        nonce_key = ctx["nonce_key"]
        ad = ctx["header"]

        aes = AESGCM(enc_key)

        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            # write header
            fout.write(ctx["header"])

            counter = 0
            while True:
                chunk = fin.read(self.chunk_size)
                if not chunk:
                    break
                nonce = _chunk_nonce(nonce_key, counter)
                ct = aes.encrypt(nonce, chunk, ad)  # cipher||tag
                tag = ct[-16:]
                cipher = ct[:-16]
                fout.write(_be32(len(cipher)))
                fout.write(cipher)
                fout.write(tag)
                counter += 1

        # best effort zero
        for k in ("enc_key", "nonce_key", "master_key"):
            b = ctx.get(k)
            if isinstance(b, bytes):
                # bytes are immutable; skip
                pass

    def decrypt_file(self, in_path: str, out_path: str, options: Dict) -> None:
        with open(in_path, "rb") as fin:
            header = self._read_header_stream(fin)
            ctx = self._init_context_for_decryption(header, options)
            ad = ctx["ad"]
            enc_key = ctx["enc_key"]
            nonce_key = ctx["nonce_key"]
            aes = AESGCM(enc_key)

            with open(out_path, "wb") as fout:
                counter = 0
                while True:
                    len_bytes = fin.read(4)
                    if len(len_bytes) == 0:
                        break
                    if len(len_bytes) < 4:
                        raise ValueError("truncated chunk length")
                    clen = _read_u32(len_bytes, 0)
                    if clen <= 0:
                        break
                    cipher = fin.read(clen)
                    if len(cipher) < clen:
                        raise ValueError("truncated cipher")
                    tag = fin.read(16)
                    if len(tag) < 16:
                        raise ValueError("missing tag")
                    nonce = _chunk_nonce(nonce_key, counter)
                    pt = aes.decrypt(nonce, cipher + tag, ad)
                    fout.write(pt)
                    counter += 1

    # ===== Internals =====
    def _read_header_stream(self, fp) -> bytes:
        prefix = fp.read(11)  # magic(5)+algo(1)+kdf(1)+flags(1)+reserved(1)+hlen(2)
        if len(prefix) < 11:
            raise ValueError("bad header")
        if prefix[:5] != MAGIC:
            raise ValueError("bad magic")
        algo = prefix[5]
        if algo != ALGO_ID:
            raise ValueError("unsupported algo")
        hlen = struct.unpack(">H", prefix[9:11])[0]
        rest = fp.read(hlen)
        if len(rest) < hlen:
            raise ValueError("truncated header")
        return prefix + rest

    def _init_context(self, options: Dict, chunked: bool) -> Dict:
        file_salt = os.urandom(16)
        algo_id = bytes([ALGO_ID])
        flags = bytes([FLAG_CHUNKED if chunked else 0])
        reserved = b"\x00"

        kdf_id = None
        header_extra = b""

        # select KDF
        if "password" in options:
            kdf_id = bytes([KDF_PASSWORD])
            pw = options["password"]
            pw_salt = os.urandom(16)
            opslimit = self.opslimit
            memlimit = self.memlimit
            master = crypto_pwhash(
                32, pw.encode("utf-8"), pw_salt, opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13
            )
            header_extra += pw_salt
            header_extra += _be32(opslimit)
            header_extra += _be32(int(memlimit // 1024))  # store KiB
        elif "raw_key" in options:
            kdf_id = bytes([KDF_RAWKEY])
            raw = _decode_key(options["raw_key"])
            if len(raw) != 32:
                raise ValueError("raw_key must be 32 bytes")
            master = raw
        elif "recipient_public" in options:
            kdf_id = bytes([KDF_X25519])
            rcpt = _decode_key(options["recipient_public"])
            if len(rcpt) != 32:
                raise ValueError("recipient_public invalid length")
            eph_sk = os.urandom(32)
            eph_pk = crypto_scalarmult_base(eph_sk)
            shared = crypto_scalarmult(eph_sk, rcpt)
            master = HKDF.derive(shared, 32, b"OTTO-E2E-MASTER", file_salt, "sha256")
            header_extra += eph_pk
        else:
            raise ValueError("Provide one of: password, raw_key, recipient_public")

        enc_key = HKDF.derive(master, 32, b"OTTO-ENC-KEY", file_salt, "sha256")
        nonce_key = HKDF.derive(master, 32, b"OTTO-NONCE-KEY", file_salt, "sha256")

        var_part = file_salt + header_extra
        header_len = _be16(len(var_part))
        header = MAGIC + algo_id + kdf_id + flags + reserved + header_len + var_part

        return {
            "header": header,
            "ad": header,
            "enc_key": enc_key,
            "nonce_key": nonce_key,
            "master_key": master,
        }

    def _init_context_for_decryption(self, header: bytes, options: Dict) -> Dict:
        if len(header) < 11:
            raise ValueError("header too short")
        if header[:5] != MAGIC:
            raise ValueError("bad magic")
        algo = header[5]
        if algo != ALGO_ID:
            raise ValueError("unsupported algo")
        kdf = header[6]
        hlen = struct.unpack(">H", header[9:11])[0]
        var_part = header[11:11+hlen]

        off = 0
        file_salt = var_part[off:off+16]; off += 16

        if kdf == KDF_PASSWORD:
            pw_salt = var_part[off:off+16]; off += 16
            opslimit = _read_u32(var_part, off); off += 4
            memKiB = _read_u32(var_part, off); off += 4
            memlimit = int(memKiB) * 1024
            pw = options.get("password")
            if not isinstance(pw, str):
                raise ValueError("Password required")
            master = crypto_pwhash(
                32, pw.encode("utf-8"), pw_salt, opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13
            )
        elif kdf == KDF_RAWKEY:
            rk = _decode_key(options.get("raw_key"))
            if len(rk) != 32:
                raise ValueError("raw_key (32 bytes) required")
            master = rk
        elif kdf == KDF_X25519:
            eph_pk = var_part[off:off+32]; off += 32
            sk = _decode_key(options.get("sender_secret"))
            if len(sk) != 32:
                raise ValueError("sender_secret invalid length")
            shared = crypto_scalarmult(sk, eph_pk)
            master = HKDF.derive(shared, 32, b"OTTO-E2E-MASTER", file_salt, "sha256")
        else:
            raise ValueError("Unknown KDF")

        enc_key = HKDF.derive(master, 32, b"OTTO-ENC-KEY", file_salt, "sha256")
        nonce_key = HKDF.derive(master, 32, b"OTTO-NONCE-KEY", file_salt, "sha256")

        return {
            "ad": header[:11+hlen],
            "enc_key": enc_key,
            "nonce_key": nonce_key,
            "master_key": master,
        }

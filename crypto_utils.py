# crypto_utils.py
import base64
import struct
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

# --- Format constants ---
# Token = base64url( header || ciphertext || tag ), no newlines
# header (AAD) = b"SC1" || u8 name_len || name_bytes || u64 counter_be || nonce(12)
MAGIC = b"SC1"
NONCE_LEN = 12
TAG_LEN = 16

# --- helpers: base64url without '=' padding ---
def _b64u_encode(b: bytes) -> str:
    s = base64.urlsafe_b64encode(b).decode("ascii")
    return s.rstrip("=")

def _b64u_decode(s: str) -> bytes:
    pad = '=' * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

# --- Strong room-code key derivation (scrypt) ---
_DOMAIN = SHA256.new(b"SecureChat v2 room key").digest()

def derive_room_key(room_code: str) -> bytes:
    rc = room_code.encode("utf-8")
    salt = SHA256.new(_DOMAIN + rc).digest()  # deterministic per room
    # Desktop-friendly but expensive enough to slow brute-force:
    return scrypt(rc, salt=salt, key_len=32, N=2**15, r=8, p=2)

def is_strong_room_code(room_code: str) -> bool:
    if not room_code:
        return False
    long_enough = len(room_code) >= 16
    wordy = len([w for w in room_code.split() if len(w) >= 3]) >= 4
    has_mix = any(c.islower() for c in room_code) and any(c.isupper() for c in room_code)
    has_digit = any(c.isdigit() for c in room_code)
    # Accept if passphrase-y (4+ words) OR 16+ chars with some variety
    return wordy or (long_enough and (has_mix or has_digit))

# --- AEAD pack/unpack helpers ---
def _build_header(sender: str, counter: int, nonce: bytes) -> bytes:
    name_bytes = sender.encode("utf-8")
    if len(name_bytes) > 255:
        name_bytes = name_bytes[:255]
    header = bytearray()
    header += MAGIC
    header += struct.pack("!B", len(name_bytes))
    header += name_bytes
    header += struct.pack("!Q", counter)  # u64 big-endian
    header += nonce  # 12 bytes
    return bytes(header)

def _parse_header(h: bytes) -> Tuple[str, int, bytes, int]:
    """
    Returns: (sender, counter, nonce, header_len)
    """
    if len(h) < 3 + 1 + 8 + NONCE_LEN:
        raise ValueError("header too short")
    if h[:3] != MAGIC:
        raise ValueError("bad magic")
    pos = 3
    name_len = h[pos]
    pos += 1
    if len(h) < 3 + 1 + name_len + 8 + NONCE_LEN:
        raise ValueError("header truncated")
    name = h[pos:pos + name_len].decode("utf-8", errors="replace")
    pos += name_len
    counter = struct.unpack("!Q", h[pos:pos + 8])[0]
    pos += 8
    nonce = h[pos:pos + NONCE_LEN]
    pos += NONCE_LEN
    return name, counter, nonce, pos

# --- Encrypt / Decrypt ---
def encrypt_message(key: bytes, sender: str, counter: int, plaintext: str) -> str:
    """
    Builds a base64url token. Header (AAD) binds sender+counter+nonce (replay-safe & anti-spoof).
    """
    nonce = get_random_bytes(NONCE_LEN)
    header = _build_header(sender, counter, nonce)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)  # AAD: authenticates header
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

    token = _b64u_encode(header + ciphertext + tag)
    return token

def decrypt_message(key: bytes, token: str) -> Tuple[str, int, str]:
    """
    Returns (sender, counter, plaintext). Raises if auth fails.
    """
    blob = _b64u_decode(token)
    sender, counter, nonce, hdr_len = _parse_header(blob)
    ciphertext_tag = blob[hdr_len:]
    if len(ciphertext_tag) < TAG_LEN:
        raise ValueError("ciphertext/tag too short")
    ciphertext = ciphertext_tag[:-TAG_LEN]
    tag = ciphertext_tag[-TAG_LEN:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(blob[:hdr_len])  # same header as AAD
    plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8", errors="replace")
    return sender, counter, plaintext
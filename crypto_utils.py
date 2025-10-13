# crypto_utils.py
import os, hmac, hashlib, binascii, secrets

def generate_salt(length=16):
    return secrets.token_bytes(length)

def to_hex(b: bytes):
    return binascii.hexlify(b).decode()

def from_hex(s: str):
    return binascii.unhexlify(s)

def derive_verifier(password: str, salt: bytes, iterations=150000):
    # PBKDF2-HMAC-SHA256
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)

def hmac_sha256(key: bytes, msg: bytes):
    return hmac.new(key, msg, hashlib.sha256).digest()

def secure_compare(a: bytes, b: bytes) -> bool:
    # constant-time compare
    return hmac.compare_digest(a, b)

def gen_nonce_hex(nbytes=16):
    return to_hex(os.urandom(nbytes))

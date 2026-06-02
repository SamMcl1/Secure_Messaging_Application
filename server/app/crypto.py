"""
Cryptographic primitives — REFERENCE IMPLEMENTATION.

IMPORTANT: The live server never encrypts or decrypts message content. End-to-end
encryption runs entirely in the client (`client/web/js/app.js`, using the Web Crypto
API): the browser generates the X25519 keypair, seals the private key under the user's
password, and performs all message AEAD. The server only ever stores and relays
ciphertext + metadata — it holds no key capable of recovering plaintext.

The key-establishment and private-key-wrapping functions below (`generate_keypair`,
`hpke_seal`, `hpke_open`, `encrypt_private_key`, `decrypt_private_key`) are a
byte-compatible Python mirror of the client-side scheme. They are kept as an
executable specification — documentation of the protocol and a cross-check for the
JavaScript — and are NOT wired into any server route. Nothing in `server/app/`
imports them. (Verify with `grep -rn hpke_seal server/`.)

The ONLY part of this module the live server actually uses is the Argon2id parameter
constants (ARGON2_*), imported by `password_utils.py` so the design document has a
single source of truth for those values.

Reference scheme mirrored here:
  Key establishment: HPKE Mode_Auth-inspired construction over X25519 + HKDF-SHA256 + AES-256-GCM.
    Follows the two-DH pattern from RFC 9180 §5.1.3 (ephemeral-static + static-static) but does
    not implement RFC 9180's LabeledExtract/LabeledExpand suite_id structure. The security
    properties (sender authentication, KEM secrecy) hold; the wire format is not interoperable
    with RFC 9180 compliant implementations.
  Password/key protection: Argon2id → HKDF-SHA256 → AES-256-GCM
"""

import os
import base64
import json

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from argon2.low_level import hash_secret_raw, Type


# ── Argon2id parameters (also used by password_utils.py) ────────────────────
# OWASP 2023 recommended minimum: time=3, memory=64 MiB, parallelism=4
ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN    = 32     # output fed into HKDF


# ── Key pair generation ──────────────────────────────────────────────────────

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 key pair for a user.

    Returns:
        (private_key_bytes, public_key_bytes) — both 32 bytes raw.
    """
    sk = X25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk_bytes, pk_bytes


# ── HKDF helper ──────────────────────────────────────────────────────────────

def _hkdf(ikm: bytes, length: int, info: bytes, salt: bytes | None = None) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


# ── Authenticated key establishment (HPKE Mode_Auth-inspired) ───────────────
# REFERENCE ONLY — not called by any server route. The live E2EE path is the
# client (client/web/js/app.js). See the module docstring.

def hpke_seal(
    sender_sk_bytes: bytes,
    sender_pk_bytes: bytes,
    recipient_pk_bytes: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[str, str]:
    """Encrypt plaintext for recipient under HPKE Mode_Auth.

    Sender authentication is provided by DH(sender_sk, recipient_pk) being
    mixed into the key derivation material — only the true sender (who holds
    sender_sk) can produce a ciphertext that decrypts successfully.

    Args:
        sender_sk_bytes:    Sender's static X25519 private key (32 B raw).
        sender_pk_bytes:    Sender's static X25519 public key (32 B raw).
        recipient_pk_bytes: Recipient's X25519 public key (32 B raw).
        plaintext:          Message bytes to encrypt.
        aad:                Associated data bound to the ciphertext (not encrypted).

    Returns:
        (eph_pub_b64, ciphertext_b64) — both base64-encoded strings.
        Store eph_pub alongside the ciphertext; the nonce is derived, not stored.
    """
    eph_sk = X25519PrivateKey.generate()
    eph_pub_bytes = eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    pk_r = X25519PublicKey.from_public_bytes(recipient_pk_bytes)
    sk_s = X25519PrivateKey.from_private_bytes(sender_sk_bytes)

    dh1 = eph_sk.exchange(pk_r)   # ephemeral-static: provides KEM secrecy
    dh2 = sk_s.exchange(pk_r)     # static-static:    provides sender auth

    ikm = dh1 + dh2
    kem_context = eph_pub_bytes + sender_pk_bytes + recipient_pk_bytes

    key   = _hkdf(ikm, 32, b"SecureMsg-v1-key"   + kem_context)
    nonce = _hkdf(ikm, 12, b"SecureMsg-v1-nonce" + kem_context)

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    return (
        base64.b64encode(eph_pub_bytes).decode(),
        base64.b64encode(ciphertext).decode(),
    )


def hpke_open(
    recipient_sk_bytes: bytes,
    sender_pk_bytes: bytes,
    eph_pub_b64: str,
    ciphertext_b64: str,
    aad: bytes = b"",
) -> bytes:
    """Decrypt a ciphertext produced by hpke_seal.

    Args:
        recipient_sk_bytes: Recipient's static X25519 private key (32 B raw).
        sender_pk_bytes:    Sender's static X25519 public key (32 B raw).
        eph_pub_b64:        Ephemeral public key stored alongside ciphertext.
        ciphertext_b64:     Encrypted message (includes 16-byte GCM auth tag).
        aad:                Associated data (must match what was passed to seal).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag if auth check fails (wrong key or tampered).
    """
    eph_pub_bytes = base64.b64decode(eph_pub_b64)
    ciphertext    = base64.b64decode(ciphertext_b64)

    sk_r = X25519PrivateKey.from_private_bytes(recipient_sk_bytes)
    recipient_pk_bytes = sk_r.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    eph_pk = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    pk_s   = X25519PublicKey.from_public_bytes(sender_pk_bytes)

    dh1 = sk_r.exchange(eph_pk)  # mirrors DH1 from seal
    dh2 = sk_r.exchange(pk_s)    # mirrors DH2 from seal (verifies sender auth)

    ikm = dh1 + dh2
    kem_context = eph_pub_bytes + sender_pk_bytes + recipient_pk_bytes

    key   = _hkdf(ikm, 32, b"SecureMsg-v1-key"   + kem_context)
    nonce = _hkdf(ikm, 12, b"SecureMsg-v1-nonce" + kem_context)

    return AESGCM(key).decrypt(nonce, ciphertext, aad)


# ── Private key encryption at rest ──────────────────────────────────────────
# REFERENCE ONLY — the browser wraps/unwraps the private key (app.js
# encryptPrivateKey/decryptPrivateKey). The server only stores the opaque
# envelope it receives; it never runs these functions.

def encrypt_private_key(private_key_bytes: bytes, password: str) -> str:
    """Protect a user's X25519 private key with their password.

    Key derivation chain:
        password + random_salt  →  Argon2id  →  32-byte PRK
        PRK  →  HKDF(info="SecureMsg-v1-key-protection")  →  32-byte AES key
        AES-256-GCM.Seal(key, random_nonce, private_key_bytes, aad="private-key")

    Returns:
        Base64-encoded JSON envelope — safe to store in the database.
    """
    salt = os.urandom(16)
    prk = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    key   = _hkdf(prk, 32, b"SecureMsg-v1-key-protection")
    nonce = os.urandom(12)

    ct = AESGCM(key).encrypt(nonce, private_key_bytes, b"private-key")

    envelope = {
        "v":     1,
        "salt":  base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct":    base64.b64encode(ct).decode(),
    }
    return base64.b64encode(json.dumps(envelope).encode()).decode()


def decrypt_private_key(envelope_b64: str, password: str) -> bytes:
    """Recover a private key from an encrypted envelope.

    Returns:
        Raw private key bytes (32 B).

    Raises:
        cryptography.exceptions.InvalidTag on wrong password or tampered envelope.
        json.JSONDecodeError / KeyError on malformed envelope.
    """
    envelope = json.loads(base64.b64decode(envelope_b64))
    salt  = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    ct    = base64.b64decode(envelope["ct"])

    prk = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    key = _hkdf(prk, 32, b"SecureMsg-v1-key-protection")
    return AESGCM(key).decrypt(nonce, ct, b"private-key")

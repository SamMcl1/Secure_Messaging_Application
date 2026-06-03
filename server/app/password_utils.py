"""
Password hashing with Argon2id.

Parameters match OWASP 2023 minimum recommendation and are kept in sync
with the constants in crypto.py so the design document has one source of truth.
"""
from argon2 import PasswordHasher, exceptions
from argon2.low_level import Type
from app.crypto import ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM


_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    type=Type.ID,
)

# Pre-computed hash used by dummy_verify so non-existent-user login attempts
# take the same time as existing-user attempts (prevents username enumeration
# via timing). Generated once at import time; never compared to real data.
_DUMMY_HASH = _hasher.hash("__timing_sentinel__")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (exceptions.VerifyMismatchError, exceptions.InvalidHashError, TypeError):
        return False


def dummy_verify(password: str) -> None:
    """Run a full Argon2id verification against a sentinel hash.

    Always returns None (the result is discarded). Called on login when the
    username does not exist so the response time matches a real failed verify.
    """
    try:
        _hasher.verify(_DUMMY_HASH, password)
    except Exception:
        pass

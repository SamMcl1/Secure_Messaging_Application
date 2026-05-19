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


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (exceptions.VerifyMismatchError, exceptions.InvalidHashError, TypeError):
        return False

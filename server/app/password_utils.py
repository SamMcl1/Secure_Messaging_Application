"""
Password hashing module.
Uses Argon2id for production-grade password hashing and verification.
"""
from argon2 import PasswordHasher, exceptions
from argon2.low_level import Type


password_hasher = PasswordHasher(type=Type.ID)


def hash_password(password):
    """
    Hash a password using Argon2id.
    """
    return password_hasher.hash(password)


def verify_password(password, password_hash):
    """
    Verify a password against a stored Argon2id hash.
    """
    try:
        return password_hasher.verify(password_hash, password)
    except (exceptions.VerifyMismatchError, exceptions.InvalidHashError, TypeError):
        return False

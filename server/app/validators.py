import re
from typing import Annotated

from flask import request, jsonify
from pydantic import BaseModel, ConfigDict, Field, field_validator, ValidationError

# Threat-detection patterns

_XSS = re.compile(
    r'<\s*(?:script|iframe|img|svg|object|embed|form|input|link|meta|style|base)\b'
    r'|\bjavascript\s*:'
    r'|\bon\w+\s*='
    r'|\bdata\s*:',
    re.IGNORECASE,
)

_SQLI = re.compile(
    r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|UNION'
    r'|EXEC(?:UTE)?|CAST|CONVERT|DECLARE)\b'
    r'|--|/\*|\*/|;',
    re.IGNORECASE,
)

_PATH_TRAVERSAL = re.compile(r'\.\.[/\\]|%2e%2e', re.IGNORECASE)

_CMD_INJECTION = re.compile(r'[;&|`]|\$[({]')

_BASE64 = re.compile(
    r'^(?:'
    r'(?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)'
    r'|'
    r'(?:(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?)'
    r')$'
)


def _reject_threats(value: str, field: str) -> str:
    """Raise ValueError if value matches any threat pattern."""
    if _XSS.search(value):
        raise ValueError(f'{field}: disallowed content (XSS pattern)')
    if _SQLI.search(value):
        raise ValueError(f'{field}: disallowed content (SQL injection pattern)')
    if _PATH_TRAVERSAL.search(value):
        raise ValueError(f'{field}: disallowed content (path traversal pattern)')
    if _CMD_INJECTION.search(value):
        raise ValueError(f'{field}: disallowed content (command injection pattern)')
    return value


# Shared annotated type
StrictPosInt = Annotated[int, Field(strict=True, gt=0)]


# Request models
class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)

    username: str
    password: str
    public_key: str            # client-generated X25519 public key (base64, 32 B)
    encrypted_private_key: str  # client-encrypted private-key envelope (base64 JSON)

    @field_validator('username')
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('username must not be empty')
        if len(v) > 64:
            raise ValueError('username must be 64 characters or fewer')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', v):
            raise ValueError('username may only contain letters, numbers, underscores, and hyphens')
        _reject_threats(v, 'username')
        return v

    @field_validator('password')
    @classmethod
    def password_valid(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('password must be at least 8 characters')
        if len(v) > 128:
            raise ValueError('password must be 128 characters or fewer')
        return v

    @field_validator('public_key')
    @classmethod
    def public_key_valid(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError('public_key must be a non-empty base64 string')
        if not _BASE64.fullmatch(v):
            raise ValueError('public_key must be valid base64')
        return v

    @field_validator('encrypted_private_key')
    @classmethod
    def encrypted_private_key_valid(cls, v: str) -> str:
        if not v or len(v) > 4096:
            raise ValueError('encrypted_private_key must be a non-empty base64 string')
        if not _BASE64.fullmatch(v):
            raise ValueError('encrypted_private_key must be valid base64')
        return v


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)

    username: str
    password: str

    @field_validator('username')
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError('invalid username')
        _reject_threats(v, 'username')
        return v

    @field_validator('password')
    @classmethod
    def password_valid(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError('invalid password')
        return v


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)

    refresh_token: str

    @field_validator('refresh_token')
    @classmethod
    def token_valid(cls, v: str) -> str:
        if not v or len(v) > 2048:
            raise ValueError('invalid refresh_token')
        return v


class LogoutRequest(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)

    refresh_token: str

    @field_validator('refresh_token')
    @classmethod
    def token_valid(cls, v: str) -> str:
        if not v or len(v) > 2048:
            raise ValueError('invalid refresh_token')
        return v


_HEX32 = re.compile(r'^(?:0x)?[0-9a-fA-F]{64}$')


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)

    recipient_id: StrictPosInt
    ciphertext: str
    eph_pub: str
    content_hash: str | None = None  # optional keccak256 of plaintext for blockchain

    @field_validator('ciphertext')
    @classmethod
    def ciphertext_valid(cls, v: str) -> str:
        if not v:
            raise ValueError('ciphertext must not be empty')
        if len(v) > 65536:
            raise ValueError('ciphertext must be 65 536 characters or fewer')
        if not _BASE64.fullmatch(v):
            raise ValueError('ciphertext must be valid base64')
        return v

    @field_validator('eph_pub')
    @classmethod
    def eph_pub_valid(cls, v: str) -> str:
        if not v:
            raise ValueError('eph_pub must not be empty')
        if len(v) > 256:
            raise ValueError('eph_pub must be 256 characters or fewer')
        if not _BASE64.fullmatch(v):
            raise ValueError('eph_pub must be valid base64')
        return v

    @field_validator('content_hash')
    @classmethod
    def content_hash_valid(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _HEX32.fullmatch(v):
            raise ValueError('content_hash must be a 32-byte hex string (0x prefix is optional)')
        return v.lower() if v.startswith('0x') else '0x' + v.lower()


ForwardMessageRequest = SendMessageRequest


# Parse helper
def parse_body(model_class):
    """
    Deserialise and validate request.get_json() against a Pydantic model.

    Returns (instance, None) on success.
    Returns (None, flask_response_tuple) on any failure so callers can do:
        body, err = parse_body(MyModel)
        if err:
            return err
    """
    data = request.get_json(silent=True)
    if data is None:
        return None, (jsonify({'message': 'Request body must be valid JSON'}), 400)
    if not isinstance(data, dict):
        return None, (jsonify({'message': 'Request body must be a JSON object'}), 400)
    try:
        instance = model_class.model_validate(data)
        return instance, None
    except ValidationError as exc:
        errors = [e['msg'] for e in exc.errors()]
        return None, (jsonify({'message': 'Validation error', 'errors': errors}), 400)

import uuid
import jwt
from datetime import datetime, timedelta
from functools import lru_cache, wraps
from flask import request, jsonify, g
import os


@lru_cache(maxsize=1)
def load_keys():
    """Load RSA keys from environment or files."""
    private_key = os.environ.get('JWT_PRIVATE_KEY')
    public_key = os.environ.get('JWT_PUBLIC_KEY')

    if private_key and public_key:
        if not private_key.strip() or not public_key.strip():
            raise RuntimeError(
                "JWT keys are configured but empty. Set non-empty JWT_PRIVATE_KEY and "
                "JWT_PUBLIC_KEY environment variables."
            )
        return private_key, public_key

    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    private_key_path = os.path.join(script_dir, 'certs', 'private_key.pem')
    public_key_path = os.path.join(script_dir, 'certs', 'public_key.pem')

    missing_paths = []
    if not os.path.exists(private_key_path):
        missing_paths.append(private_key_path)
    if not os.path.exists(public_key_path):
        missing_paths.append(public_key_path)

    if missing_paths:
        raise RuntimeError(
            "JWT RSA key files are missing: {}. Provide both files at the default "
            "certs location or set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY environment "
            "variables.".format(", ".join(missing_paths))
        )

    with open(private_key_path, 'r') as f:
        private_key = f.read()
    with open(public_key_path, 'r') as f:
        public_key = f.read()

    if not private_key.strip() or not public_key.strip():
        raise RuntimeError(
            "JWT RSA key files are empty. Ensure both private_key.pem and "
            "public_key.pem contain valid RSA keys."
        )

    return private_key, public_key


def create_tokens(user_id, username):
    """Create access and refresh tokens, each with a unique JTI."""
    private_key, _ = load_keys()
    now = datetime.utcnow()

    access_payload = {
        'user_id': user_id,
        'username': username,
        'type': 'access',
        'jti': str(uuid.uuid4()),
        'exp': now + timedelta(hours=1),
        'iat': now,
    }

    refresh_payload = {
        'user_id': user_id,
        'username': username,
        'type': 'refresh',
        'jti': str(uuid.uuid4()),
        'exp': now + timedelta(days=7),
        'iat': now,
    }

    access_token = jwt.encode(access_payload, private_key, algorithm='RS256')
    refresh_token = jwt.encode(refresh_payload, private_key, algorithm='RS256')

    return access_token, refresh_token


def verify_token(token, token_type='access'):
    """Verify and decode a JWT token."""
    _, public_key = load_keys()

    try:
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        if payload.get('type') != token_type:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """Decorator to protect routes with JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'message': 'Invalid Authorization header'}), 401

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        payload = verify_token(token, token_type='access')
        if not payload:
            return jsonify({'message': 'Invalid or expired token'}), 401

        jti = payload.get('jti')
        if not jti:
            return jsonify({'message': 'Invalid token structure'}), 401

        # Server-side denylist check — catches tokens revoked via /auth/logout
        from app.db import query as _db_query
        if _db_query('SELECT 1 FROM revoked_tokens WHERE jti = %s', (jti,)):
            return jsonify({'message': 'Token has been revoked'}), 401

        g.user_id = payload['user_id']
        g.username = payload['username']
        g.jti = jti
        g.token_exp = payload['exp']

        return f(*args, **kwargs)

    return decorated

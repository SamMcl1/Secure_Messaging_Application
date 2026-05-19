import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
import os


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
    """Create access and refresh tokens."""
    private_key, _ = load_keys()
    
    # Access token (1 hour)
    access_payload = {
        'user_id': user_id,
        'username': username,
        'type': 'access',
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
    
    # Refresh token (7 days)
    refresh_payload = {
        'user_id': user_id,
        'username': username,
        'type': 'refresh',
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow()
    }
    
    access_token = jwt.encode(access_payload, private_key, algorithm='RS256')
    refresh_token = jwt.encode(refresh_payload, private_key, algorithm='RS256')
    
    return access_token, refresh_token


def verify_token(token, token_type='access'):
    """Verify and decode a JWT token."""
    _, public_key = load_keys()
    
    try:
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        
        # Check token type
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
        
        # Check for token in Authorization header
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
        
        # Attach user_id to request context
        request.user_id = payload['user_id']
        request.username = payload['username']
        
        return f(*args, **kwargs)
    
    return decorated

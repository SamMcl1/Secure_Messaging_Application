import base64
from flask import Blueprint, request, jsonify, g
from app.models import User
from app.jwt_utils import create_tokens, verify_token, token_required
from app.crypto import generate_keypair, encrypt_private_key

auth = Blueprint('auth', __name__, url_prefix='/auth')


@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required'}), 400

    username = data['username']
    password = data['password']

    if User.get_by_username(username):
        return jsonify({'message': 'Username already exists'}), 409

    # Generate X25519 keypair for this user.
    # Public key is stored plaintext so others can encrypt to this user (TOFU).
    # Private key is wrapped under the user's password and never stored raw.
    sk_bytes, pk_bytes = generate_keypair()
    public_key = base64.b64encode(pk_bytes).decode()
    encrypted_private_key = encrypt_private_key(sk_bytes, password)

    user = User.create(username, password, public_key, encrypted_private_key)

    if not user:
        if User.get_by_username(username):
            return jsonify({'message': 'Username already exists'}), 409
        return jsonify({'message': 'Failed to create user'}), 500

    access_token, refresh_token = create_tokens(user.user_id, user.username)

    return jsonify({
        'message': 'User registered successfully',
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key,
        'encrypted_private_key': user.encrypted_private_key,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
    }), 201


@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required'}), 400

    user = User.get_by_username(data['username'])

    if not user or not user.verify_password(data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token, refresh_token = create_tokens(user.user_id, user.username)

    return jsonify({
        'message': 'Login successful',
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key,
        # Return the encrypted key envelope so the client can unlock it locally
        # with the password it already has in memory. Server never sees raw sk.
        'encrypted_private_key': user.encrypted_private_key,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
    }), 200


@auth.route('/refresh', methods=['POST'])
def refresh():
    data = request.get_json()

    if not data or not data.get('refresh_token'):
        return jsonify({'message': 'Refresh token is required'}), 400

    payload = verify_token(data['refresh_token'], token_type='refresh')

    if not payload:
        return jsonify({'message': 'Invalid or expired refresh token'}), 401

    access_token, new_refresh_token = create_tokens(payload['user_id'], payload['username'])

    return jsonify({
        'message': 'Token refreshed successfully',
        'access_token': access_token,
        'refresh_token': new_refresh_token,
        'token_type': 'Bearer',
    }), 200


@auth.route('/me', methods=['GET'])
@token_required
def get_current_user():
    user = User.get_by_id(g.user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    return jsonify({
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key,
        'encrypted_private_key': user.encrypted_private_key,
    }), 200


@auth.route('/users/<username>/pubkey', methods=['GET'])
@token_required
def get_pubkey(username):
    """Return a user's X25519 public key for TOFU key establishment.

    The caller should cache this fingerprint locally. If it changes on a
    subsequent call the client should warn the user (key change event).
    """
    user = User.get_by_username(username)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    return jsonify({
        'username': user.username,
        'public_key': user.public_key,
    }), 200

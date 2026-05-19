from flask import Blueprint, jsonify, g
from app.models import User
from app.jwt_utils import create_tokens, verify_token, token_required
from app.validators import parse_body, RegisterRequest, LoginRequest, RefreshRequest

auth = Blueprint('auth', __name__, url_prefix='/auth')


@auth.route('/register', methods=['POST'])
def register():
    body, err = parse_body(RegisterRequest)
    if err:
        return err

    if User.get_by_username(body.username):
        return jsonify({'message': 'Username already exists'}), 409

    user = User.create(body.username, body.password, body.public_key)
    if not user:
        if User.get_by_username(body.username):
            return jsonify({'message': 'Username already exists'}), 409
        return jsonify({'message': 'Failed to create user'}), 500

    access_token, refresh_token = create_tokens(user.user_id, user.username)

    return jsonify({
        'message': 'User registered successfully',
        'user_id': user.user_id,
        'username': user.username,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer'
    }), 201


@auth.route('/login', methods=['POST'])
def login():
    body, err = parse_body(LoginRequest)
    if err:
        return err

    user = User.get_by_username(body.username)
    if not user or not user.verify_password(body.password):
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token, refresh_token = create_tokens(user.user_id, user.username)

    return jsonify({
        'message': 'Login successful',
        'user_id': user.user_id,
        'username': user.username,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer'
    }), 200


@auth.route('/refresh', methods=['POST'])
def refresh():
    body, err = parse_body(RefreshRequest)
    if err:
        return err

    payload = verify_token(body.refresh_token, token_type='refresh')
    if not payload:
        return jsonify({'message': 'Invalid or expired refresh token'}), 401

    access_token, new_refresh_token = create_tokens(payload['user_id'], payload['username'])

    return jsonify({
        'message': 'Token refreshed successfully',
        'access_token': access_token,
        'refresh_token': new_refresh_token,
        'token_type': 'Bearer'
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
        'public_key': user.public_key
    }), 200

from datetime import datetime, timezone

from flask import Blueprint, jsonify, g
from app.models import User, RevokedToken
from app.jwt_utils import create_tokens, verify_token, token_required
from app.validators import parse_body, RegisterRequest, LoginRequest, RefreshRequest, LogoutRequest
from app.extensions import limiter

auth = Blueprint('auth', __name__, url_prefix='/auth')


@auth.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
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
@limiter.limit("10 per minute")
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


@auth.route('/logout', methods=['POST'])
@token_required
def logout():
    body, err = parse_body(LogoutRequest)
    if err:
        return err

    refresh_payload = verify_token(body.refresh_token, token_type='refresh')
    if not refresh_payload:
        return jsonify({'message': 'Invalid or expired refresh token'}), 401

    if refresh_payload.get('user_id') != g.user_id:
        return jsonify({'message': 'Refresh token does not match authenticated user'}), 401

    refresh_jti = refresh_payload.get('jti')
    refresh_exp = refresh_payload.get('exp')
    if not refresh_jti or not refresh_exp:
        return jsonify({'message': 'Invalid refresh token structure'}), 401

    access_expires_at = datetime.fromtimestamp(g.token_exp, tz=timezone.utc)
    refresh_expires_at = datetime.fromtimestamp(refresh_exp, tz=timezone.utc)

    if not RevokedToken.add(g.jti, g.user_id, access_expires_at):
        return jsonify({'message': 'Failed to revoke token'}), 500

    if not RevokedToken.add(refresh_jti, g.user_id, refresh_expires_at):
        return jsonify({'message': 'Failed to revoke token'}), 500

    return jsonify({'message': 'Logged out successfully'}), 200


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

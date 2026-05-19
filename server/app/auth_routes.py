from flask import Blueprint, request, jsonify
from app.models import User, Database
from app.jwt_utils import create_tokens, verify_token, token_required

auth = Blueprint('auth', __name__, url_prefix='/auth')


@auth.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required'}), 400
    
    username = data.get('username')
    password = data.get('password')
    public_key = data.get('public_key', '')
    
    # Check if username already exists
    if User.get_by_username(username):
        return jsonify({'message': 'Username already exists'}), 409
    
    # Create new user
    user = User.create(username, password, public_key)
    
    if not user:
        return jsonify({'message': 'Failed to create user'}), 500
    
    # Create tokens
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
    """Login user."""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    # Get user from database
    user = User.get_by_username(username)
    
    if not user or not user.verify_password(password):
        return jsonify({'message': 'Invalid username or password'}), 401
    
    # Create tokens
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
    """Refresh access token using refresh token."""
    data = request.get_json()
    
    if not data or not data.get('refresh_token'):
        return jsonify({'message': 'Refresh token is required'}), 400
    
    refresh_token = data.get('refresh_token')
    
    # Verify refresh token
    payload = verify_token(refresh_token, token_type='refresh')
    
    if not payload:
        return jsonify({'message': 'Invalid or expired refresh token'}), 401
    
    user_id = payload['user_id']
    username = payload['username']
    
    # Create new tokens
    access_token, new_refresh_token = create_tokens(user_id, username)
    
    return jsonify({
        'message': 'Token refreshed successfully',
        'access_token': access_token,
        'refresh_token': new_refresh_token,
        'token_type': 'Bearer'
    }), 200


@auth.route('/me', methods=['GET'])
@token_required
def get_current_user():
    """Get current authenticated user."""
    user = User.get_by_id(request.user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key
    }), 200

from flask import Blueprint, request, jsonify, g
from app.models import Message, User
from app.jwt_utils import token_required

messages = Blueprint('messages', __name__)


def _can_access(msg, user_id):
    """True if user is sender, recipient, or holds a non-revoked access grant."""
    if msg['sender_id'] == user_id or msg['recipient_id'] == user_id:
        return True
    return Message.has_access(msg['id'], user_id)


def _validate_recipient_id(value):
    """Return (int, None) on success, (None, response) on failure."""
    if not isinstance(value, int) or isinstance(value, bool):
        return None, (jsonify({'message': 'recipient_id must be an integer'}), 400)
    if value <= 0:
        return None, (jsonify({'message': 'recipient_id must be a positive integer'}), 400)
    return value, None


def _validate_string_field(value, name):
    """Return (str, None) on success, (None, response) on failure."""
    if not isinstance(value, str) or not value.strip():
        return None, (jsonify({'message': f'{name} must be a non-empty string'}), 400)
    return value, None


@messages.route('/', methods=['POST'])
@token_required
def send_message():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Request body required'}), 400

    recipient_id, err = _validate_recipient_id(data.get('recipient_id'))
    if err:
        return err

    ciphertext, err = _validate_string_field(data.get('ciphertext'), 'ciphertext')
    if err:
        return err

    nonce, err = _validate_string_field(data.get('nonce'), 'nonce')
    if err:
        return err

    if not User.get_by_id(recipient_id):
        return jsonify({'message': 'Recipient not found'}), 404

    msg = Message.create(g.user_id, recipient_id, ciphertext, nonce)
    if not msg:
        return jsonify({'message': 'Failed to send message'}), 500

    return jsonify({
        'message_id': msg.message_id,
        'sender_id': msg.sender_id,
        'recipient_id': msg.recipient_id
    }), 201


@messages.route('/', methods=['GET'])
@token_required
def list_messages():
    rows = Message.get_for_user(g.user_id)
    return jsonify(rows), 200


@messages.route('/<int:message_id>', methods=['GET'])
@token_required
def get_message(message_id):
    msg = Message.get_by_id(message_id)
    if not msg:
        return jsonify({'message': 'Message not found'}), 404
    if not _can_access(msg, g.user_id):
        return jsonify({'message': 'Access denied'}), 403
    return jsonify(msg), 200


@messages.route('/<int:message_id>/forward', methods=['POST'])
@token_required
def forward_message(message_id):
    msg = Message.get_by_id(message_id)
    if not msg:
        return jsonify({'message': 'Message not found'}), 404
    if not _can_access(msg, g.user_id):
        return jsonify({'message': 'Access denied'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'message': 'Request body required'}), 400

    recipient_id, err = _validate_recipient_id(data.get('recipient_id'))
    if err:
        return err

    ciphertext, err = _validate_string_field(data.get('ciphertext'), 'ciphertext')
    if err:
        return err

    nonce, err = _validate_string_field(data.get('nonce'), 'nonce')
    if err:
        return err

    if not User.get_by_id(recipient_id):
        return jsonify({'message': 'Recipient not found'}), 404

    new_msg = Message.create(g.user_id, recipient_id, ciphertext, nonce)
    if not new_msg:
        return jsonify({'message': 'Failed to forward message'}), 500

    return jsonify({
        'message_id': new_msg.message_id,
        'sender_id': new_msg.sender_id,
        'recipient_id': new_msg.recipient_id
    }), 201


@messages.route('/<int:message_id>/access/<int:target_user_id>', methods=['POST'])
@token_required
def grant_access(message_id, target_user_id):
    msg = Message.get_by_id(message_id)
    if not msg:
        return jsonify({'message': 'Message not found'}), 404
    if not _can_access(msg, g.user_id):
        return jsonify({'message': 'Access denied'}), 403

    if not User.get_by_id(target_user_id):
        return jsonify({'message': 'User not found'}), 404

    if msg['sender_id'] == target_user_id or msg['recipient_id'] == target_user_id:
        return jsonify({'message': 'User already has access as sender or recipient'}), 409

    if not Message.grant_access(message_id, target_user_id):
        return jsonify({'message': 'Failed to grant access'}), 500

    return jsonify({'message': 'Access granted'}), 200


@messages.route('/<int:message_id>/access/<int:target_user_id>', methods=['DELETE'])
@token_required
def revoke_access(message_id, target_user_id):
    msg = Message.get_by_id(message_id)
    if not msg:
        return jsonify({'message': 'Message not found'}), 404
    if not _can_access(msg, g.user_id):
        return jsonify({'message': 'Access denied'}), 403

    if not Message.has_access(message_id, target_user_id):
        return jsonify({'message': 'No active access grant found'}), 404

    if not Message.revoke_access(message_id, target_user_id):
        return jsonify({'message': 'Failed to revoke access'}), 500

    return jsonify({'message': 'Access revoked'}), 200

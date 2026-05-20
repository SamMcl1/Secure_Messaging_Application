from flask import Blueprint, jsonify, g
from app.models import Message, User
from app.jwt_utils import token_required
from app.validators import parse_body, SendMessageRequest, ForwardMessageRequest
from app.extensions import limiter
from app import blockchain

messages = Blueprint('messages', __name__)


def _can_access(msg, user_id):
    """True if user is sender, recipient, or holds a non-revoked access grant."""
    if msg['sender_id'] == user_id or msg['recipient_id'] == user_id:
        return True
    return Message.has_access(msg['id'], user_id)


def _can_manage_access(msg, user_id):
    """True only for the original sender."""
    return msg['sender_id'] == user_id


@messages.route('/', methods=['POST'])
@limiter.limit("60 per minute")
@token_required
def send_message():
    body, err = parse_body(SendMessageRequest)
    if err:
        return err

    if body.recipient_id == g.user_id:
        return jsonify({'message': 'Cannot send a message to yourself'}), 400

    if not User.get_by_id(body.recipient_id):
        return jsonify({'message': 'Recipient not found'}), 404

    msg = Message.create(g.user_id, body.recipient_id, body.ciphertext, body.eph_pub)
    if not msg:
        return jsonify({'message': 'Failed to send message'}), 500

    tx_hash = None
    if body.content_hash:
        tx_hash = blockchain.record_digest(body.content_hash)
        if tx_hash:
            Message.set_tx_hash(msg.message_id, tx_hash)

    return jsonify({
        'message_id':   msg.message_id,
        'sender_id':    msg.sender_id,
        'recipient_id': msg.recipient_id,
        'tx_hash':      tx_hash,
    }), 201


@messages.route('/', methods=['GET'])
@limiter.limit("60 per minute")
@token_required
def list_messages():
    rows = Message.get_for_user(g.user_id)
    return jsonify(rows), 200


@messages.route('/<int:message_id>', methods=['GET'])
@limiter.limit("120 per minute")
@token_required
def get_message(message_id):
    msg = Message.get_by_id(message_id)
    if not msg:
        return jsonify({'message': 'Message not found'}), 404
    if not _can_access(msg, g.user_id):
        return jsonify({'message': 'Access denied'}), 403
    return jsonify(msg), 200


@messages.route('/<int:message_id>/forward', methods=['POST'])
@limiter.limit("30 per minute")
@token_required
def forward_message(message_id):
    msg = Message.get_by_id(message_id)
    if not msg:
        return jsonify({'message': 'Message not found'}), 404
    if not _can_access(msg, g.user_id):
        return jsonify({'message': 'Access denied'}), 403

    body, err = parse_body(ForwardMessageRequest)
    if err:
        return err

    if body.recipient_id == g.user_id:
        return jsonify({'message': 'Cannot forward a message to yourself'}), 400

    if not User.get_by_id(body.recipient_id):
        return jsonify({'message': 'Recipient not found'}), 404

    new_msg = Message.create(g.user_id, body.recipient_id, body.ciphertext, body.eph_pub)
    if not new_msg:
        return jsonify({'message': 'Failed to forward message'}), 500

    return jsonify({
        'message_id': new_msg.message_id,
        'sender_id': new_msg.sender_id,
        'recipient_id': new_msg.recipient_id,
    }), 201


@messages.route('/<int:message_id>/access/<int:target_user_id>', methods=['POST'])
@limiter.limit("30 per minute")
@token_required
def grant_access(message_id, target_user_id):
    msg = Message.get_by_id(message_id)
    if not msg:
        return jsonify({'message': 'Message not found'}), 404
    if not _can_manage_access(msg, g.user_id):
        return jsonify({'message': 'Access denied'}), 403

    if not User.get_by_id(target_user_id):
        return jsonify({'message': 'User not found'}), 404

    if msg['sender_id'] == target_user_id or msg['recipient_id'] == target_user_id:
        return jsonify({'message': 'User already has access as sender or recipient'}), 409

    if not Message.grant_access(message_id, target_user_id):
        return jsonify({'message': 'Failed to grant access'}), 500

    return jsonify({'message': 'Access granted'}), 200


@messages.route('/<int:message_id>/access/<int:target_user_id>', methods=['DELETE'])
@limiter.limit("30 per minute")
@token_required
def revoke_access(message_id, target_user_id):
    msg = Message.get_by_id(message_id)
    if not msg:
        return jsonify({'message': 'Message not found'}), 404
    if not _can_manage_access(msg, g.user_id):
        return jsonify({'message': 'Access denied'}), 403

    if not Message.has_access(message_id, target_user_id):
        return jsonify({'message': 'No active access grant found'}), 404

    if not Message.revoke_access(message_id, target_user_id):
        return jsonify({'message': 'Failed to revoke access'}), 500

    return jsonify({'message': 'Access revoked'}), 200

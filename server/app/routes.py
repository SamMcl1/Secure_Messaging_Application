import threading
import time

from flask import Blueprint, jsonify, g, current_app
from app.models import Message, User
from app.jwt_utils import token_required
from app.validators import parse_body, SendMessageRequest, ForwardMessageRequest
from app.extensions import limiter
from app import blockchain

messages = Blueprint('messages', __name__)

# Per-user blockchain rate limit — max 10 on-chain records per hour per user.
# This prevents any single account from draining the deployer wallet's gas.
_bc_rate: dict[int, list] = {}
_bc_rate_lock = threading.Lock()


def _blockchain_rate_ok(user_id: int, max_per_hour: int = 10) -> bool:
    now = time.monotonic()
    with _bc_rate_lock:
        recent = [t for t in _bc_rate.get(user_id, []) if now - t < 3600]
        if len(recent) >= max_per_hour:
            return False
        recent.append(now)
        _bc_rate[user_id] = recent
    return True


def _record_and_store(app, message_id: int, content_hash: str):
    """Run blockchain.record_digest in a background thread so the HTTP response returns fast."""
    with app.app_context():
        tx = blockchain.record_digest(content_hash)
        if tx:
            Message.set_tx_hash(message_id, tx)


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

    if body.content_hash and _blockchain_rate_ok(g.user_id):
        # Fire-and-forget — the transaction is submitted in the background so
        # the API response isn't held up waiting for the chain to confirm.
        # The tx_hash is stored in the DB once the RPC call comes back.
        app = current_app._get_current_object()
        threading.Thread(
            target=_record_and_store,
            args=(app, msg.message_id, body.content_hash),
            daemon=True,
        ).start()

    return jsonify({
        'message_id':   msg.message_id,
        'sender_id':    msg.sender_id,
        'recipient_id': msg.recipient_id,
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


@messages.route('/<int:message_id>', methods=['DELETE'])
@limiter.limit("30 per minute")
@token_required
def delete_message(message_id):
    msg = Message.get_by_id(message_id)
    if not msg:
        return jsonify({'message': 'Message not found'}), 404

    # Only the sender or recipient can delete a message outright. Users who
    # only hold a shared access grant should have their access revoked instead
    # (DELETE /<id>/access/<user_id>) rather than destroying it for everyone.
    if msg['sender_id'] != g.user_id and msg['recipient_id'] != g.user_id:
        return jsonify({'message': 'Access denied'}), 403

    if not Message.delete(message_id):
        return jsonify({'message': 'Failed to delete message'}), 500

    return jsonify({'message': 'Message deleted'}), 200


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

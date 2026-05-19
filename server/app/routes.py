from flask import Blueprint, request, jsonify, g
from app.models import User, Message
from app.jwt_utils import token_required

messages = Blueprint('messages', __name__)


@messages.route('/', methods=['POST'])
@token_required
def send_message():
    """Store a pre-encrypted message envelope.

    The client performs HPKE seal locally and POSTs the resulting
    ciphertext + eph_pub. The server stores opaque blobs — it cannot decrypt.

    Expected body:
        recipient_username  str   — who the message is for
        ciphertext          str   — base64 AES-256-GCM ciphertext (includes tag)
        eph_pub             str   — base64 ephemeral X25519 public key
        aad                 str   — associated data used during encryption (optional)
    """
    data = request.get_json()

    if not data:
        return jsonify({'message': 'Request body required'}), 400

    missing = [f for f in ('recipient_username', 'ciphertext', 'eph_pub') if not data.get(f)]
    if missing:
        return jsonify({'message': f'Missing fields: {", ".join(missing)}'}), 400

    recipient = User.get_by_username(data['recipient_username'])
    if not recipient:
        return jsonify({'message': 'Recipient not found'}), 404

    if recipient.user_id == g.user_id:
        return jsonify({'message': 'Cannot send a message to yourself'}), 400

    msg = Message.create(
        sender_id=g.user_id,
        recipient_id=recipient.user_id,
        ciphertext=data['ciphertext'],
        eph_pub=data['eph_pub'],
    )

    if not msg:
        return jsonify({'message': 'Failed to store message'}), 500

    return jsonify({
        'message': 'Message sent',
        'message_id': msg.message_id,
    }), 201


@messages.route('/', methods=['GET'])
@token_required
def list_messages():
    """Return all messages sent to or from the authenticated user.

    Each row includes sender_username and sender_public_key so the client
    has everything it needs to call hpke_open without a second round-trip.
    """
    rows = Message.get_for_user(g.user_id)

    return jsonify({
        'messages': [
            {
                'id': row['id'],
                'sender_id': row['sender_id'],
                'sender_username': row['sender_username'],
                'sender_public_key': row['sender_public_key'],
                'recipient_id': row['recipient_id'],
                'recipient_username': row['recipient_username'],
                'ciphertext': row['ciphertext'],
                'eph_pub': row['eph_pub'],
                'created_at': row['created_at'].isoformat() if row['created_at'] else None,
            }
            for row in rows
        ]
    }), 200


@messages.route('/<int:message_id>', methods=['GET'])
@token_required
def get_message(message_id):
    """Return a single message by ID.

    Only the sender or recipient may fetch it.
    Response includes sender_public_key so the recipient can call hpke_open.
    """
    row = Message.get_by_id(message_id)

    if not row:
        return jsonify({'message': 'Message not found'}), 404

    if g.user_id not in (row['sender_id'], row['recipient_id']):
        return jsonify({'message': 'Access denied'}), 403

    return jsonify({
        'id': row['id'],
        'sender_id': row['sender_id'],
        'sender_username': row['sender_username'],
        'sender_public_key': row['sender_public_key'],
        'recipient_id': row['recipient_id'],
        'recipient_username': row['recipient_username'],
        'ciphertext': row['ciphertext'],
        'eph_pub': row['eph_pub'],
        'created_at': row['created_at'].isoformat() if row['created_at'] else None,
    }), 200

from flask import current_app

from app.db import query, execute, get_conn
from app.password_utils import hash_password, verify_password


class User:

    def __init__(self, username, public_key=None, encrypted_private_key=None, user_id=None):
        self.user_id = user_id
        self.username = username
        self.public_key = public_key
        self.encrypted_private_key = encrypted_private_key

    @staticmethod
    def create(username, password, public_key, encrypted_private_key):
        """Insert a new user. Returns User on success, None if username taken."""
        password_hash = hash_password(password)
        try:
            user_id = execute(
                '''INSERT INTO users (username, password_hash, public_key, encrypted_private_key)
                   VALUES (%s, %s, %s, %s) RETURNING id''',
                (username, password_hash, public_key, encrypted_private_key)
            )
            return User(username, public_key=public_key,
                        encrypted_private_key=encrypted_private_key, user_id=user_id)
        except Exception:
            current_app.logger.exception('User.create failed for username=%r', username)
            return None

    @staticmethod
    def get_by_username(username):
        """Fetch a user row by username. Returns User or None."""
        rows = query(
            '''SELECT id, username, password_hash, public_key, encrypted_private_key
               FROM users WHERE username = %s''',
            (username,)
        )
        if not rows:
            return None
        row = rows[0]
        user = User(
            row['username'],
            public_key=row['public_key'],
            encrypted_private_key=row.get('encrypted_private_key'),
            user_id=row['id'],
        )
        user.password_hash = row['password_hash']
        return user

    @staticmethod
    def get_by_id(user_id):
        """Fetch a user row by ID. Returns User or None."""
        rows = query(
            '''SELECT id, username, password_hash, public_key, encrypted_private_key
               FROM users WHERE id = %s''',
            (user_id,)
        )
        if not rows:
            return None
        row = rows[0]
        user = User(
            row['username'],
            public_key=row['public_key'],
            encrypted_private_key=row.get('encrypted_private_key'),
            user_id=row['id'],
        )
        user.password_hash = row['password_hash']
        return user

    def verify_password(self, password):
        if not hasattr(self, 'password_hash'):
            return False
        return verify_password(password, self.password_hash)


class Message:

    def __init__(self, message_id, sender_id, recipient_id, ciphertext, eph_pub, created_at=None):
        self.message_id = message_id
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.ciphertext = ciphertext
        self.eph_pub = eph_pub
        self.created_at = created_at

    @staticmethod
    def create(sender_id, recipient_id, ciphertext, eph_pub):
        """Insert a new message. Returns Message on success, None on failure."""
        try:
            message_id = execute(
                '''INSERT INTO messages (sender_id, recipient_id, ciphertext, eph_pub)
                   VALUES (%s, %s, %s, %s) RETURNING id''',
                (sender_id, recipient_id, ciphertext, eph_pub)
            )
            return Message(message_id, sender_id, recipient_id, ciphertext, eph_pub)
        except Exception:
            current_app.logger.exception(
                'Message.create failed sender_id=%r recipient_id=%r', sender_id, recipient_id
            )
            return None

    @staticmethod
    def get_for_user(user_id):
        """Return all messages the user can access: sender, recipient, or explicitly granted."""
        return query(
            '''SELECT m.id, m.sender_id, m.recipient_id, m.ciphertext, m.eph_pub,
                      m.created_at,
                      s.username AS sender_username, s.public_key AS sender_public_key,
                      r.username AS recipient_username
               FROM messages m
               JOIN users s ON s.id = m.sender_id
               JOIN users r ON r.id = m.recipient_id
               WHERE m.sender_id = %s OR m.recipient_id = %s
                  OR m.id IN (
                      SELECT message_id FROM message_access
                      WHERE user_id = %s AND revoked_at IS NULL
                  )
               ORDER BY m.created_at DESC''',
            (user_id, user_id, user_id)
        )

    @staticmethod
    def get_by_id(message_id):
        """Fetch a single message with sender info. Returns dict or None."""
        rows = query(
            '''SELECT m.id, m.sender_id, m.recipient_id, m.ciphertext, m.eph_pub,
                      m.created_at,
                      s.username AS sender_username, s.public_key AS sender_public_key,
                      r.username AS recipient_username
               FROM messages m
               JOIN users s ON s.id = m.sender_id
               JOIN users r ON r.id = m.recipient_id
               WHERE m.id = %s''',
            (message_id,)
        )
        return rows[0] if rows else None

    @staticmethod
    def has_access(message_id, user_id):
        """Return True if user has a non-revoked explicit access grant."""
        rows = query(
            'SELECT 1 FROM message_access WHERE message_id = %s AND user_id = %s AND revoked_at IS NULL',
            (message_id, user_id)
        )
        return bool(rows)

    @staticmethod
    def grant_access(message_id, user_id):
        """Insert or restore an access grant. Returns True on success, False on DB error."""
        try:
            execute(
                '''INSERT INTO message_access (message_id, user_id)
                   VALUES (%s, %s)
                   ON CONFLICT (message_id, user_id)
                   DO UPDATE SET revoked_at = NULL, granted_at = NOW()''',
                (message_id, user_id)
            )
            return True
        except Exception:
            current_app.logger.exception(
                'Message.grant_access failed message_id=%r user_id=%r', message_id, user_id
            )
            return False

    @staticmethod
    def revoke_access(message_id, user_id):
        """Set revoked_at on an existing grant. Returns True only if a grant was revoked."""
        try:
            rows = query(
                '''UPDATE message_access
                   SET revoked_at = NOW()
                   WHERE message_id = %s AND user_id = %s AND revoked_at IS NULL
                   RETURNING message_id''',
                (message_id, user_id)
            )
            return bool(rows)
        except Exception:
            current_app.logger.exception(
                'Message.revoke_access failed message_id=%r user_id=%r', message_id, user_id
            )
            return False


class RevokedToken:

    @staticmethod
    def add(jti, user_id, expires_at):
        """Record a revoked JWT JTI. Returns True on success, False on DB error."""
        try:
            execute(
                '''INSERT INTO revoked_tokens (jti, user_id, expires_at)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (jti) DO NOTHING''',
                (jti, user_id, expires_at)
            )
            return True
        except Exception:
            current_app.logger.exception('RevokedToken.add failed jti=%r user_id=%r', jti, user_id)
            return False

    @staticmethod
    def add_many(revocations):
        """Record multiple revoked JWT JTIs atomically. Returns True on success, False on DB error."""
        if not revocations:
            return True
        try:
            conn = get_conn()
            with conn.cursor() as cur:
                cur.executemany(
                    '''INSERT INTO revoked_tokens (jti, user_id, expires_at)
                       VALUES (%s, %s, %s)
                       ON CONFLICT (jti) DO NOTHING''',
                    revocations
                )
            return True
        except Exception:
            current_app.logger.exception('RevokedToken.add_many failed count=%d', len(revocations))
            return False

from app.db import query, execute, get_conn
from app.password_utils import hash_password, verify_password


class User:

    def __init__(self, username, password=None, public_key=None, user_id=None):
        self.user_id = user_id
        self.username = username
        self.password = password
        self.public_key = public_key

    @staticmethod
    def create(username, password, public_key=''):
        """Insert a new user into Supabase. Returns User on success, None if username taken."""
        password_hash = hash_password(password)
        try:
            user_id = execute(
                'INSERT INTO users (username, password_hash, public_key) VALUES (%s, %s, %s) RETURNING id',
                (username, password_hash, public_key)
            )
            return User(username, public_key=public_key, user_id=user_id)
        except Exception:
            return None

    @staticmethod
    def get_by_username(username):
        """Fetch a user row by username. Returns User or None."""
        rows = query(
            'SELECT id, username, password_hash, public_key FROM users WHERE username = %s',
            (username,)
        )
        if not rows:
            return None
        row = rows[0]
        user = User(row['username'], public_key=row['public_key'], user_id=row['id'])
        user.password_hash = row['password_hash']
        return user

    @staticmethod
    def get_by_id(user_id):
        """Fetch a user row by ID. Returns User or None."""
        rows = query(
            'SELECT id, username, password_hash, public_key FROM users WHERE id = %s',
            (user_id,)
        )
        if not rows:
            return None
        row = rows[0]
        user = User(row['username'], public_key=row['public_key'], user_id=row['id'])
        user.password_hash = row['password_hash']
        return user

    def verify_password(self, password):
        if not hasattr(self, 'password_hash'):
            return False
        return verify_password(password, self.password_hash)


class Message:

    def __init__(self, message_id, sender_id, recipient_id, ciphertext, nonce, created_at=None):
        self.message_id = message_id
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.created_at = created_at

    @staticmethod
    def create(sender_id, recipient_id, ciphertext, nonce):
        """Insert a new message. Returns Message on success, None on failure."""
        try:
            message_id = execute(
                'INSERT INTO messages (sender_id, recipient_id, ciphertext, nonce) VALUES (%s, %s, %s, %s) RETURNING id',
                (sender_id, recipient_id, ciphertext, nonce)
            )
            return Message(message_id, sender_id, recipient_id, ciphertext, nonce)
        except Exception:
            return None

    @staticmethod
    def get_for_user(user_id):
        """Return all messages the user can access: sender, recipient, or explicitly granted."""
        return query(
            '''SELECT * FROM messages
               WHERE sender_id = %s OR recipient_id = %s
                  OR id IN (
                      SELECT message_id FROM message_access
                      WHERE user_id = %s AND revoked_at IS NULL
                  )
               ORDER BY created_at DESC''',
            (user_id, user_id, user_id)
        )

    @staticmethod
    def get_by_id(message_id):
        """Fetch a single message by ID."""
        rows = query('SELECT * FROM messages WHERE id = %s', (message_id,))
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
        """Insert or restore an access grant for user. Returns True on success, False on DB error."""
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
            return False

    @staticmethod
    def revoke_access(message_id, user_id):
        """Set revoked_at on an existing access grant. Returns True only if a grant was revoked."""
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
            return False

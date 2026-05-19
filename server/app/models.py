import sqlite3
import os
from app.password_utils import hash_password, verify_password


class Database:
    """Database connection helper."""
    
    @staticmethod
    def get_db():
        """Get database connection."""
        db_path = os.environ.get('DATABASE_PATH', 'database/hangover.db')
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def init_db():
        """Initialize database with schema."""
        db_path = os.environ.get('DATABASE_PATH', 'database/hangover.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Read and execute schema
        schema_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'schema.sql')
        with open(schema_path, 'r') as f:
            cursor.executescript(f.read())
        
        conn.commit()
        conn.close()


class User:
    """User model for authentication."""
    
    def __init__(self, username, password=None, public_key=None, user_id=None):
        self.user_id = user_id
        self.username = username
        self.password = password
        self.public_key = public_key
    
    @staticmethod
    def create(username, password, public_key=''):
        """Create a new user in the database."""
        conn = Database.get_db()
        cursor = conn.cursor()
        
        try:
            password_hash = hash_password(password)
            cursor.execute(
                'INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)',
                (username, password_hash, public_key)
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return User(username, public_key=public_key, user_id=user_id)
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    @staticmethod
    def get_by_username(username):
        """Get user by username."""
        conn = Database.get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, password_hash, public_key FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            user = User(row['username'], public_key=row['public_key'], user_id=row['id'])
            user.password_hash = row['password_hash']
            return user
        return None
    
    @staticmethod
    def get_by_id(user_id):
        """Get user by ID."""
        conn = Database.get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, password_hash, public_key FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            user = User(row['username'], public_key=row['public_key'], user_id=row['id'])
            user.password_hash = row['password_hash']
            return user
        return None
    
    def verify_password(self, password):
        """Verify password against stored hash."""
        if not hasattr(self, 'password_hash'):
            return False
        return verify_password(password, self.password_hash)


class Message:
    """Message model."""
    pass

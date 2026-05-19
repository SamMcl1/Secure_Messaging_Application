import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Flask session signing key — must be set; no insecure fallback
    SECRET_KEY = os.environ.get('SECRET_KEY')

    # Debug — reads FLASK_DEBUG env var; defaults off so prod stays safe
    DEBUG = os.getenv('FLASK_DEBUG', '0') == '1'

    # CORS — set to the exact client origin (e.g. https://app.example.com).
    # For local development, prefer an explicit localhost origin (e.g. http://localhost:3000).
    # Leave unset to deny all cross-origin requests.
    ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', '')

    # Supabase
    SUPABASE_URL = os.environ['SUPABASE_URL']
    SUPABASE_SERVICE_KEY = os.environ['SUPABASE_SERVICE_KEY']

    # Direct PostgreSQL URL (psycopg2)
    DATABASE_URL = os.environ['DATABASE_URL']

    # Payload size cap (enforced by Flask before any route runs)
    MAX_CONTENT_LENGTH = 128 * 1024  # 128 KB

    # Blockchain
    SEPOLIA_RPC_URL = os.environ.get('SEPOLIA_RPC_URL', '')
    CONTRACT_ADDRESS = os.environ.get('CONTRACT_ADDRESS', '')

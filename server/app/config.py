import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'change-this-in-production')

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

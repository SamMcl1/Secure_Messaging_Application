import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'change-this-in-production')
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'database/hangover.db')

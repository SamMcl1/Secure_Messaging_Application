"""
wsgi.py — Gunicorn entry point for production deployment.

Run with:
    gunicorn -w 4 -b 127.0.0.1:8000 wsgi:app

Local dev (Werkzeug only — not for production):
    python run.py
"""
from app import create_app

app = create_app()

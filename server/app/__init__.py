import logging
import re

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_talisman import Talisman
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .db import init_db, close_conn
from .extensions import limiter


_REDACT_RE = re.compile(
    r'(\$argon2[a-z]+\$[^\s"\',;]+)'                              # Argon2 hash
    r'|(ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'  # JWT
    r'|(-----BEGIN[A-Z ]+KEY-----[\s\S]*?-----END[A-Z ]+KEY-----)'  # PEM key block
)

_SENSITIVE_KEYS = frozenset({
    'password', 'password_hash', 'private_key', 'secret_key',
    'service_key', 'access_token', 'refresh_token', 'token',
    'authorization', 'jwt_private_key',
})


class SensitiveDataFilter(logging.Filter):
    """Scrub credentials and crypto material from log records before they are emitted."""

    def filter(self, record):
        if isinstance(record.args, dict):
            record.args = {
                k: '[REDACTED]' if k.lower() in _SENSITIVE_KEYS else v
                for k, v in record.args.items()
            }
        try:
            msg = record.getMessage()
            redacted = _REDACT_RE.sub('[REDACTED]', msg)
            if redacted != msg:
                record.msg = redacted
                record.args = None
        except Exception:
            pass
        return True


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    if not app.config.get('SECRET_KEY'):
        raise RuntimeError(
            "SECRET_KEY environment variable must be set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    app.logger.addFilter(SensitiveDataFilter())

    proxy_count = app.config.get('TRUSTED_PROXY_COUNT', 0)
    if proxy_count:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=proxy_count, x_host=proxy_count)

    Talisman(
        app,
        force_https=app.config.get('FORCE_HTTPS', False),
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        content_security_policy={
            # API-only server — block everything by default.
            # Adjust if HTML responses are ever added.
            'default-src': "'none'",
            'frame-ancestors': "'none'",
        },
        x_content_type_options=True,
        frame_options='DENY',
    )

    init_db(app)
    app.teardown_appcontext(close_conn)
    limiter.init_app(app)

    allowed_origin = app.config.get('ALLOWED_ORIGIN', '')
    if allowed_origin:
        CORS(
            app,
            origins=[allowed_origin],
            methods=['GET', 'POST', 'DELETE'],
            allow_headers=['Authorization', 'Content-Type'],
        )

    from .auth_routes import auth
    from .routes import messages
    app.register_blueprint(auth)
    app.register_blueprint(messages, url_prefix='/messages')

    @app.before_request
    def enforce_json_content_type():
        if request.method in ('POST', 'PUT', 'PATCH') and (request.content_length or 0) > 0:
            ct = request.content_type or ''
            if not ct.startswith('application/json'):
                return jsonify({'message': 'Content-Type must be application/json'}), 415

    @app.errorhandler(413)
    def payload_too_large(_e):
        return jsonify({'message': 'Request payload exceeds the 128 KB limit'}), 413

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({'message': 'Not found'}), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({'message': 'Method not allowed'}), 405

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        if isinstance(e, HTTPException):
            return jsonify({'message': e.description}), e.code
        app.logger.exception('Unhandled exception: %s', e)
        return jsonify({'message': 'Internal server error'}), 500

    return app

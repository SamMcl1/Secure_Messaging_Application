from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from .config import Config
from .db import init_db, close_conn
from .extensions import limiter


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    if not app.config.get('SECRET_KEY'):
        raise RuntimeError(
            "SECRET_KEY environment variable must be set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
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

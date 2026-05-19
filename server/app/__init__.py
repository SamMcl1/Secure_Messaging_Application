from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException
from .config import Config
from .db import init_db, close_conn


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    init_db(app)
    app.teardown_appcontext(close_conn)

    from .auth_routes import auth
    from .routes import messages
    app.register_blueprint(auth)
    app.register_blueprint(messages, url_prefix='/messages')

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({'message': 'Not found'}), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({'message': 'Method not allowed'}), 405

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        if isinstance(e, HTTPException):
            return e
        app.logger.exception('Unhandled exception: %s', e)
        return jsonify({'message': 'Internal server error'}), 500

    return app

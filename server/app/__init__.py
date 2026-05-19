from flask import Flask
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

    return app

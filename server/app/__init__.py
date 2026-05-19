from flask import Flask
from app.models import Database
from app.auth_routes import auth


def create_app():
    app = Flask(__name__)
    
    # Initialize database
    Database.init_db()
    
    # Register blueprints
    app.register_blueprint(auth)
    
    return app

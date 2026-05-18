from flask import Blueprint

auth = Blueprint('auth', __name__)
messages = Blueprint('messages', __name__)

# Auth routes:    /auth/register  /auth/login  /auth/logout  /auth/password
# Message routes: /messages/  /messages/<id>  /messages/<id>/forward  /messages/<id>/access/<uid>

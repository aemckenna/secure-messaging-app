# main.py
from flask import Flask
from views.auth_routes import auth_bp
from views.messaging_routes import messaging_bp
import secrets
from flask_socketio import SocketIO

app = Flask(__name__)

app.register_blueprint(auth_bp)
app.register_blueprint(messaging_bp)
app.secret_key = secrets.token_hex(16)
socketio = SocketIO(app)

if __name__ == '__main__':
    app.run(debug=True)
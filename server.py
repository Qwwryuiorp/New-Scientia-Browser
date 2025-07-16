   from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import time

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

users = {}  # { username: password_hash }
online_clients = {}  # { username: sid }
rate_limits = {}  # { ip: [timestamps] }

def is_rate_limited(ip):
    now = time.time()
    limit = 10
    window = 60
    if ip not in rate_limits:
        rate_limits[ip] = []
    rate_limits[ip] = [t for t in rate_limits[ip] if now - t < window]
    if len(rate_limits[ip]) >= limit:
        return True
    rate_limits[ip].append(now)
    return False

@app.route('/register', methods=['POST'])
def register():
    ip = request.remote_addr
    if is_rate_limited(ip):
        return jsonify({'status': 'error', 'message': 'Too many requests'}), 429
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'}), 400
    if username in users:
        return jsonify({'status': 'error', 'message': 'Username already taken'}), 409
    users[username] = generate_password_hash(password)
    return jsonify({'status': 'success', 'message': 'Account created'}), 201

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    if is_rate_limited(ip):
        return jsonify({'status': 'error', 'message': 'Too many requests'}), 429
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'}), 400
    if username not in users or not check_password_hash(users[username], password):
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
    return jsonify({'status': 'success'}), 200

@socketio.on('identify')
def handle_identify(data):
    username = data.get('username')
    if username:
        online_clients[username] = request.sid
        print(f"{username} identified with SID {request.sid}")

@socketio.on('chat')
def handle_chat(data):
    try:
        sender = data.get('sender')
        recipient = data.get('recipient')
        message = data.get('message')
        if not sender or not recipient or not message:
            print("Invalid chat format")
            return
        if recipient in online_clients:
            emit('chat', data, to=online_clients[recipient])
        else:
            print(f"Recipient {recipient} not online")
    except Exception as e:
        print(f"Chat error: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    for username, sid in list(online_clients.items()):
        if sid == request.sid:
            del online_clients[username]
            print(f"{username} disconnected")
            break

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000) 

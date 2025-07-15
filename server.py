from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory "database"
users = {}  # { username: password_hash }
online_clients = {}  # { username: sid }
rate_limits = {}  # { ip: [timestamps] }

# === HELPER: RATE LIMITING ===
def is_rate_limited(ip):
    now = time.time()
    limit = 10  # max requests
    window = 60  # seconds
    if ip not in rate_limits:
        rate_limits[ip] = []
    rate_limits[ip] = [t for t in rate_limits[ip] if now - t < window]
    if len(rate_limits[ip]) >= limit:
        return True
    rate_limits[ip].append(now)
    return False

# === API: Register ===
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

# === API: Login ===
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

# === SOCKET: Client identifies who they are ===
@socketio.on('identify')
def handle_identify(data):
    username = data.get('username')
    if not username:
        return
    online_clients[username] = request.sid
    print(f"{username} connected with SID {request.sid}")

# === SOCKET: Send message ===
@socketio.on('chat')
def handle_chat(json):
    sender = json.get('sender')
    recipient = json.get('recipient')
    message = json.get('message')

    if recipient in online_clients:
        emit('chat', json, to=online_clients[recipient])
    else:
        print(f"User {recipient} not online")

# === SOCKET: Disconnect ===
@socketio.on('disconnect')
def handle_disconnect():
    disconnected = None
    for user, sid in list(online_clients.items()):
        if sid == request.sid:
            disconnected = user
            del online_clients[user]
            break
    if disconnected:
        print(f"{disconnected} disconnected")

# === Run Flask Server ===
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)

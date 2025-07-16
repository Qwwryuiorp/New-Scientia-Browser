import time
import eventlet
eventlet.monkey_patch()

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# In-memory storage
users = {}  # { username: hashed_password }
online_clients = {}  # { username: sid }
rate_limits = {}  # { ip_address: [timestamps] }

# === RATE LIMITING ===
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

# === REGISTER ===
@app.route('/register', methods=['POST'])
def register():
    ip = request.remote_addr
    if is_rate_limited(ip):
        return jsonify({'status': 'error', 'message': 'Too many requests'}), 429
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'status': 'error', 'message': 'Invalid JSON'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'}), 400
    if username in users:
        return jsonify({'status': 'error', 'message': 'Username already taken'}), 409

    users[username] = generate_password_hash(password)
    return jsonify({'status': 'success', 'message': 'Account created'}), 201

# === LOGIN ===
@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    if is_rate_limited(ip):
        return jsonify({'status': 'error', 'message': 'Too many requests'}), 429
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'status': 'error', 'message': 'Invalid JSON'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'}), 400
    if username not in users or not check_password_hash(users[username], password):
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

    return jsonify({'status': 'success'}), 200

# === IDENTIFY (SOCKET INIT) ===
@socketio.on('identify')
def handle_identify(data):
    username = data.get('username')
    if username:
        online_clients[username] = request.sid
        print(f"[CONNECT] {username} connected with SID {request.sid}")

# === CHAT SOCKET ===
@socketio.on('chat')
def handle_chat(data):
    try:
        sender = data.get('sender')
        recipient = data.get('recipient')
        message = data.get('message')

        if not sender or not recipient or not message:
            print("[WARN] Incomplete message payload")
            return

        if recipient in online_clients:
            emit('chat', {
                'sender': sender,
                'message': message
            }, to=online_clients[recipient])
            print(f"[CHAT] {sender} → {recipient}: {message}")
        else:
            print(f"[INFO] {recipient} not online")

    except Exception as e:
        print(f"[ERROR] Chat message failed: {e}")

# === DISCONNECT SOCKET ===
@socketio.on('disconnect')
def handle_disconnect():
    disconnected_user = None
    for user, sid in list(online_clients.items()):
        if sid == request.sid:
            disconnected_user = user
            del online_clients[user]
            break
    if disconnected_user:
        print(f"[DISCONNECT] {disconnected_user} has disconnected.")

# === RUN SERVER ===
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)

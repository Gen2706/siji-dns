#!/usr/bin/env python3
"""siji-DNS Auth API"""

import hashlib, time, hmac, base64, json
from flask import Blueprint, request, jsonify, current_app
from core.database import get_conn

auth_bp = Blueprint('auth', __name__)

def _make_token(user_id, username, role, secret):
    payload = json.dumps({'uid': user_id, 'u': username, 'r': role, 'exp': time.time() + 3600})
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    token = base64.b64encode(f"{payload}.{sig}".encode()).decode()
    return token

def verify_token(token, secret):
    try:
        decoded = base64.b64decode(token.encode()).decode()
        payload_str, sig = decoded.rsplit('.', 1)
        expected = hmac.new(secret.encode(), payload_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(payload_str)
        if payload['exp'] < time.time():
            return None
        return payload
    except Exception:
        return None

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Unauthorized'}), 401
        payload = verify_token(token, current_app.config['SECRET_KEY'])
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        payload = verify_token(token, current_app.config['SECRET_KEY'])
        if not payload or payload.get('r') != 'admin':
            return jsonify({'error': 'Admin required'}), 403
        request.user = payload
        return f(*args, **kwargs)
    return decorated

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    with get_conn() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, pw_hash)
        ).fetchone()
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        conn.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user['id'],))
        token = _make_token(user['id'], user['username'], user['role'],
                           current_app.config['SECRET_KEY'])
        return jsonify({'token': token, 'username': user['username'], 'role': user['role']})

@auth_bp.route('/me', methods=['GET'])
@require_auth
def me():
    return jsonify(request.user)

@auth_bp.route('/change-password', methods=['POST'])
@require_auth
def change_password():
    data = request.json or {}
    old_pw = hashlib.sha256(data.get('old_password','').encode()).hexdigest()
    new_pw = hashlib.sha256(data.get('new_password','').encode()).hexdigest()
    with get_conn() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE id=? AND password=?",
            (request.user['uid'], old_pw)
        ).fetchone()
        if not user:
            return jsonify({'error': 'Wrong current password'}), 400
        conn.execute("UPDATE users SET password=? WHERE id=?", (new_pw, user['id']))
    return jsonify({'message': 'Password changed'})

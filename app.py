import os
import re
import sqlite3
import hashlib
import hmac
import secrets
import logging
from contextlib import closing

from flask import Flask, request, jsonify, render_template_string, session, abort
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=4096, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_SECURE=True,
                  PERMANENT_SESSION_LIFETIME=1800)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

def read_secret(name):
    path = os.getenv(name + '_FILE')
    value = open(path, encoding='ascii').read().strip() if path else os.getenv(name)
    if not value:
        raise RuntimeError(f'{name} is not configured')
    return value

# Get encryption key from environment variable
encryption_key = read_secret('ENCRYPTION_KEY')
cipher = Fernet(encryption_key.encode())
app.secret_key = read_secret('FLASK_SECRET')

# Database file path
DB_FILE = os.getenv('DB_FILE', '/usr/src/app/db/keys.db')
MAX_STORED_TOKENS = 1000

# Function to initialize the database if it doesn't exist
def initialize_db():
    if os.path.exists(DB_FILE) and not os.path.isfile(DB_FILE):
        raise RuntimeError("database path is not a file")
    try:
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        conn = sqlite3.connect(DB_FILE, timeout=5)
        conn.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_key BLOB NOT NULL,
            key_hash TEXT NOT NULL
        )
        ''')
        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_keys_hash_unique ON keys(key_hash)')
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        logging.error('database initialization failed (%s)', type(exc).__name__)
        raise

initialize_db()

@app.before_request
def request_guards():
    if request.method == 'POST' and request.path != '/api/key-status' and 'application/json' not in request.headers.get('Accept', ''):
        token = session.get('csrf_token', '')
        if not token or not hmac.compare_digest(token, request.form.get('csrf_token', '')):
            abort(400, description='invalid request token')

# HTML template for the landing page
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebOS-TR</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #1a1a1a;
            color: white;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }
        .container {
            text-align: center;
            width: 400px;
            margin: 0 auto; /* Center the container */
        }
        input {
            padding: 10px;
            margin: 10px 2px 10px 0;
            width: 300px;
            border-radius: 5px;
            border: 1px solid #444;
            background-color: #333;
            color: white;
            text-align: center;
            line-height: 1.5;
        }
        button {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            background-color: #5c6bc0;
            color: white;
            cursor: pointer;
            margin: 2px;
        }
        button:hover {
            background-color: #3f4c8c;
        }
        button.remove {
            background-color: #d9534f; /* Soft red */
        }
        button.remove:hover {
            background-color: #c9302c; /* Slightly darker red */
        }
        .message {
            margin: 10px auto;
            padding: 10px;
            background-color: #2e2e2e;
            border-radius: 5px;
            color: lightgreen;
            width: 100%; /* Match container width */
            text-align: center;
        }
        .message.duplicate,
        .message.not-found {
            color: yellow;
        }
        .message.invalid {
            color: red;
        }
        .description {
            margin-top: 15px;
            font-size: 14px;
            color: #ccc;
            text-align: center;
        }
        .footer {
            position: absolute;
            bottom: 10px;
            font-size: 14px;
            color: #777;
        }
        .footer a {
            color: #5c6bc0;
            text-decoration: none;
        }
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>WebOS Token Refresher</h1>
        <form action="/" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="text" name="key" placeholder="Enter your token" required>
            <button type="submit" name="action" value="add">Add Token</button>
            <button type="submit" name="action" value="remove" class="remove">Remove Token</button>
        </form>
        {% if message %}
        <div class="message 
            {% if 'duplicate' in message %}duplicate{% endif %}
            {% if 'invalid token format' in message %}invalid{% endif %}
            {% if 'not found in database' in message %}not-found{% endif %}
        ">{{ message }}</div>
        {% endif %}

        <p class="description">
            This page allows you to securely add or remove your developer mode session token for LG WebOS. Tokens are hashed, encrypted, stored, and periodically refreshed with the LG Developer API to keep your session active.
        </p>
    </div>
    <div class="footer">
        <p>Check out the source code on <a href="https://github.com/LucifersCircle/webOS-Token-Refresh" target="_blank">GitHub</a>.</p>
    </div>
</body>
</html>
"""

@app.route('/api/key-status', methods=['POST'])
def key_status():
    """Check registration using only the existing SHA-256 token hash."""
    key_hash = request.form.get('key_hash', '')
    if not re.fullmatch(r'[a-fA-F0-9]{64}', key_hash):
        response = jsonify({'error': 'a valid SHA-256 key_hash is required'})
        response.status_code = 400
    else:
        try:
            # Opening in read-only mode also prevents creating a missing database.
            with closing(sqlite3.connect(f'file:{DB_FILE}?mode=ro', uri=True)) as conn:
                registered = conn.execute(
                    'SELECT 1 FROM keys WHERE key_hash = ? LIMIT 1',
                    (key_hash.lower(),),
                ).fetchone() is not None
            response = jsonify({'registered': registered})
        except sqlite3.Error:
            response = jsonify({'error': 'unable to check token registration'})
            response.status_code = 503
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.after_request
def security_headers(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    return response


# Landing page route
@app.route('/', methods=['GET', 'POST'])
def manage_key():
    message = None
    is_api_request = 'application/json' in request.headers.get('Accept', '')

    if request.method == 'POST':
        key = request.form.get('key')
        action = request.form.get('action')

        if action not in ('add', 'remove'):
            return (jsonify({'error': 'invalid action'}), 400) if is_api_request else (render_template_string(HTML_TEMPLATE, message='invalid action', csrf_token=session.get('csrf_token', '')), 400)

        if not key:
            if is_api_request:
                return jsonify({'error': 'token is required'}), 400
            message = "token is required"
            return render_template_string(HTML_TEMPLATE, message=message, csrf_token=session.get('csrf_token', ''))

        # Validate the key format
        if not re.fullmatch(r'^[a-fA-F0-9]{64}$', key):
            if is_api_request:
                return jsonify({'error': 'invalid token format - expected 64 hexadecimal characters'}), 400
            message = "invalid token format - expected 64 hexadecimal characters"
            return render_template_string(HTML_TEMPLATE, message=message, csrf_token=session.get('csrf_token', ''))

        conn = None
        try:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            conn = sqlite3.connect(DB_FILE, timeout=5)
            conn.execute('BEGIN IMMEDIATE')

            if action == 'add':
                cursor = conn.execute("SELECT COUNT(*) FROM keys WHERE key_hash = ?", (key_hash,))
                if cursor.fetchone()[0] > 0:
                    if is_api_request:
                        return jsonify({'error': 'duplicate token hash detected - rejecting'}), 409
                    message = "duplicate token hash detected - rejecting"
                    return render_template_string(HTML_TEMPLATE, message=message, csrf_token=session.get('csrf_token', ''))

                total = conn.execute('SELECT COUNT(*) FROM keys').fetchone()[0]
                if total >= MAX_STORED_TOKENS:
                    if is_api_request:
                        return jsonify({'error': 'token capacity reached'}), 429
                    return render_template_string(HTML_TEMPLATE, message='token capacity reached', csrf_token=session.get('csrf_token', '')), 429

                encrypted_key = cipher.encrypt(key.encode())
                conn.execute('INSERT INTO keys (encrypted_key, key_hash) VALUES (?, ?)', (encrypted_key, key_hash))
                conn.commit()
                if is_api_request:
                    return jsonify({'message': 'token added successfully'}), 201
                message = "token added successfully"
                return render_template_string(HTML_TEMPLATE, message=message, csrf_token=session.get('csrf_token', ''))

            elif action == 'remove':
                cursor = conn.execute("SELECT COUNT(*) FROM keys WHERE key_hash = ?", (key_hash,))
                if cursor.fetchone()[0] == 0:
                    if is_api_request:
                        return jsonify({'error': 'token hash not found in database'}), 404
                    message = "token hash not found in database"
                    return render_template_string(HTML_TEMPLATE, message=message, csrf_token=session.get('csrf_token', ''))

                conn.execute("DELETE FROM keys WHERE key_hash = ?", (key_hash,))
                conn.commit()
                if is_api_request:
                    return jsonify({'message': 'token removed successfully'}), 200
                message = "token removed successfully"
                return render_template_string(HTML_TEMPLATE, message=message, csrf_token=session.get('csrf_token', ''))

            else:
                if is_api_request:
                    return jsonify({'error': 'invalid action'}), 400
                message = "invalid action"
                return render_template_string(HTML_TEMPLATE, message=message, csrf_token=session.get('csrf_token', ''))

        except Exception as exc:
            logging.error('token management operation failed (%s)', type(exc).__name__)
            if is_api_request:
                return jsonify({'error': 'operation failed'}), 500
            message = "operation failed"
            return render_template_string(HTML_TEMPLATE, message=message, csrf_token=session.get('csrf_token', '')), 500
        finally:
            if conn is not None:
                conn.close()

    # Render HTML for GET requests
    if request.method == 'GET':
        session['csrf_token'] = secrets.token_urlsafe(32)
        session.permanent = True
    return render_template_string(HTML_TEMPLATE, message=message, csrf_token=session.get('csrf_token', ''))



if __name__ == '__main__':
    initialize_db() # Initialize database on startup
    app.run(host='0.0.0.0', port=5000)

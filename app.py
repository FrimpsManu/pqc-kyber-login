"""Login website whose credentials are protected with Kyber768 (ML-KEM-768).

Login flow
  1. Browser asks /api/handshake. The server makes a fresh Kyber key pair,
     keeps the secret key in memory and returns the public key + an id.
  2. Browser encapsulates against that public key (ML-KEM-768 in JS), gets a
     32-byte shared secret, and AES-256-GCM-encrypts {username, password}.
  3. Browser posts the Kyber ciphertext + encrypted credentials.
  4. Server decapsulates with the official C code, decrypts, checks the
     password hash. Each handshake key is used once and expires.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from functools import wraps

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (Flask, g, jsonify, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from pqc import hybrid, kyber

ASSIGNMENT_MESSAGE = "Dear All Good luck with your Job interview with Bloomberg"
HANDSHAKE_TTL = 120  # seconds
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get("DATABASE_PATH", os.path.join(app.instance_path, "users.db")),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
)

# --- database ---------------------------------------------------------------

def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            " id INTEGER PRIMARY KEY,"
            " username TEXT UNIQUE NOT NULL COLLATE NOCASE,"
            " password_hash TEXT NOT NULL,"
            " created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# --- one-time Kyber handshake keys -----------------------------------------

_pending = {}
_pending_lock = threading.Lock()


def new_handshake():
    public_key, secret_key = kyber.keypair()
    kid = secrets.token_urlsafe(16)
    now = time.time()
    with _pending_lock:
        for k in [k for k, (_, exp) in _pending.items() if exp < now]:
            del _pending[k]
        _pending[kid] = (secret_key, now + HANDSHAKE_TTL)
    return kid, public_key


def take_handshake(kid):
    with _pending_lock:
        entry = _pending.pop(kid, None)
    if entry is None or entry[1] < time.time():
        return None
    return entry[0]


def b64d(value):
    return base64.b64decode(value, validate=True)


def b64e(data):
    return base64.b64encode(data).decode()


def open_credentials(purpose):
    """Decrypt a Kyber-protected credentials request. Returns (creds, trace)."""
    body = request.get_json(silent=True) or {}
    secret_key = take_handshake(str(body.get("kid", "")))
    if secret_key is None:
        raise ValueError("Secure session expired. Please try again.")
    try:
        kem_ct = b64d(body["kem_ciphertext"])
        nonce = b64d(body["nonce"])
        ciphertext = b64d(body["ciphertext"])
        shared_secret = kyber.decapsulate(kem_ct, secret_key)
        # The handshake id and purpose are bound in as associated data.
        aad = f"{purpose}:{body['kid']}".encode()
        creds = json.loads(AESGCM(shared_secret).decrypt(nonce, ciphertext, aad))
    except (KeyError, ValueError, InvalidTag, json.JSONDecodeError):
        raise ValueError("Could not read the encrypted request.")
    trace = {
        "purpose": purpose,
        "time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "public_key_bytes": kyber.PUBLICKEYBYTES,
        "kem_ciphertext_bytes": len(kem_ct),
        "kem_ciphertext_head": kem_ct[:24].hex(),
        "payload_bytes": len(ciphertext),
        "payload_b64": b64e(ciphertext),
        "nonce": nonce.hex(),
        # A fingerprint only - the shared secret itself is never shown.
        "secret_fingerprint": hashlib.sha256(shared_secret).hexdigest()[:16],
    }
    return creds, trace

# --- pages ------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.get("/")
def index():
    return redirect(url_for("dashboard" if "user" in session else "login"))


@app.get("/login")
def login():
    return render_template("auth.html", mode="login")


@app.get("/signup")
def signup():
    return render_template("auth.html", mode="signup")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    result = None
    message = ASSIGNMENT_MESSAGE
    if request.method == "POST":
        message = request.form.get("message", "").strip()[:2000] or ASSIGNMENT_MESSAGE
        result = encrypt_demo(message)
    return render_template("dashboard.html", user=session["user"],
                           trace=session.get("trace"), message=message,
                           result=result)


def encrypt_demo(message):
    public_key, secret_key = kyber.keypair()
    sent = hybrid.encrypt(public_key, message.encode())
    plaintext, receiver_secret = hybrid.decrypt(
        secret_key, sent["kem_ciphertext"], sent["nonce"], sent["ciphertext"])
    decrypted = plaintext.decode()
    return {
        "public_key": public_key.hex(),
        "kem_ciphertext": sent["kem_ciphertext"].hex(),
        "sender_secret": sent["shared_secret"].hex(),
        "receiver_secret": receiver_secret.hex(),
        "nonce": sent["nonce"].hex(),
        "ciphertext_hex": sent["ciphertext"].hex(),
        "ciphertext_b64": b64e(sent["ciphertext"]),
        "ciphertext_bytes": len(sent["ciphertext"]),
        "decrypted": decrypted,
        "secrets_match": receiver_secret == sent["shared_secret"],
        "text_matches": decrypted == message,
    }

# --- JSON API used by static/js/auth.js -------------------------------------

@app.post("/api/handshake")
def api_handshake():
    kid, public_key = new_handshake()
    return jsonify(kid=kid, public_key=b64e(public_key))


@app.post("/api/signup")
def api_signup():
    try:
        creds, trace = open_credentials("signup")
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    username = str(creds.get("username", "")).strip()
    password = str(creds.get("password", ""))
    if not USERNAME_RE.match(username):
        return jsonify(error="Username: 3-32 letters, numbers, dots, dashes or underscores."), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   (username, generate_password_hash(password, method="pbkdf2:sha256")))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="That username is taken."), 409
    session.clear()
    session["user"] = username
    session["trace"] = trace
    return jsonify(redirect=url_for("dashboard"))


@app.post("/api/login")
def api_login():
    try:
        creds, trace = open_credentials("login")
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    username = str(creds.get("username", "")).strip()
    password = str(creds.get("password", ""))
    row = get_db().execute("SELECT username, password_hash FROM users WHERE username = ?",
                           (username,)).fetchone()
    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify(error="Wrong username or password."), 401
    session.clear()
    session["user"] = row["username"]
    session["trace"] = trace
    return jsonify(redirect=url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 8000)))

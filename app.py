import os
import re
import time
import sqlite3
import logging
import secrets
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect,
    session, flash, url_for, g, abort
)
from flask_bcrypt import Bcrypt
import pyotp

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,         # set True if served over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

bcrypt = Bcrypt(app)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
DATABASE = "users.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


app.teardown_appcontext(close_db)


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            secret      TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            last_login  TEXT
        )
    """)
    # Migrate existing tables that lack new columns
    existing_cols = {
        row[1].lower()
        for row in db.execute("PRAGMA table_info(users)").fetchall()
    }
    for col, col_def in [
        ("secret", "TEXT NOT NULL DEFAULT ''"),
        ("created_at", "TEXT NOT NULL DEFAULT (datetime('now'))"),
        ("last_login", "TEXT"),
    ]:
        if col not in existing_cols:
            try:
                db.execute(f"ALTER TABLE users ADD COLUMN {col} {col_def}")
            except sqlite3.OperationalError:
                pass
    db.commit()


with app.app_context():
    init_db()

# ---------------------------------------------------------------------------
# In-memory rate limiter (login attempts)
# ---------------------------------------------------------------------------
_attempts = {}          # key -> [count, first_attempt_timestamp]
_MAX_ATTEMPTS = 5
_LOCKOUT_MINUTES = 15


def _rate_limit_key():
    """Identify caller by IP for rate-limiting purposes."""
    return request.remote_addr or "unknown"


def _is_locked_out(key):
    if key not in _attempts:
        return False
    count, first = _attempts[key]
    if count >= _MAX_ATTEMPTS:
        if time.time() - first < _LOCKOUT_MINUTES * 60:
            return True
        del _attempts[key]          # lockout expired
    return False


def _record_attempt(key, success):
    if success:
        _attempts.pop(key, None)
        return
    now = time.time()
    if key in _attempts:
        c, _ = _attempts[key]
        _attempts[key] = [c + 1, now]
    else:
        _attempts[key] = [1, now]


def _remaining_attempts(key):
    if key not in _attempts:
        return _MAX_ATTEMPTS
    count, _ = _attempts[key]
    return max(0, _MAX_ATTEMPTS - count)

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{4,30}$")
_PASSWORD_MIN = 6


def validate_username(raw):
    u = raw.strip()
    if len(u) < 4:
        return None
    if not _USERNAME_RE.match(u):
        return None
    return u


def validate_password(raw):
    p = raw
    if len(p) < _PASSWORD_MIN:
        return "Password must be at least 6 characters"
    return None  # valid


# ---------------------------------------------------------------------------
# CSRF simple token
# ---------------------------------------------------------------------------
def _generate_csrf():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def _validate_csrf(token):
    return token == session.get("_csrf_token")


@app.context_processor
def inject_csrf():
    return {"csrf_token": _generate_csrf()}

# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp

# ---------------------------------------------------------------------------
# Routes – Home
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    if "user" in session:
        return render_template("dashboard.html", user=session["user"])
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Routes – Register
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not _validate_csrf(request.form.get("csrf_token", "")):
            abort(400)
        username = validate_username(request.form.get("username", ""))
        if not username:
            flash("Invalid username (4–30 chars, letters / digits / underscores only)", "error")
            return render_template("register.html")

        pwd_err = validate_password(request.form.get("password", ""))
        if pwd_err:
            flash(pwd_err, "error")
            return render_template("register.html")

        password = request.form["password"]
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        secret = pyotp.random_base32()

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, secret) VALUES (?, ?, ?)",
                (username, hashed, secret),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists", "error")
            return render_template("register.html")

        logger.info("New user registered: %s", username)

        # Store 2FA info temporarily so login page can display it
        provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, issuer_name="THIRANEX Secure Login"
        )
        session["show_2fa_setup"] = {
            "username": username,
            "secret": secret,
            "provisioning_uri": provisioning_uri,
        }

        flash(
            "Registration successful! "
            "Set up your authenticator app below, then sign in.",
            "success",
        )
        return redirect(url_for("login"))

    return render_template("register.html")

# ---------------------------------------------------------------------------
# Routes – Login
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not _validate_csrf(request.form.get("csrf_token", "")):
            abort(400)
        rl_key = _rate_limit_key()
        if _is_locked_out(rl_key):
            flash(
                f"Too many failed attempts. Try again in {_LOCKOUT_MINUTES} minutes.",
                "error",
            )
            logger.warning("Rate-limited login from %s", rl_key)
            show_2fa = session.get("show_2fa_setup")
            return render_template("login.html", show_2fa=show_2fa)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and bcrypt.check_password_hash(user["password"], password):
            _record_attempt(rl_key, success=True)
            session["temp_user"] = user["username"]
            session.permanent = True
            logger.info("Successful password login for %s", username)
            return redirect(url_for("otp"))

        _record_attempt(rl_key, success=False)
        remaining = _remaining_attempts(rl_key)
        flash(f"Invalid username or password ({remaining} attempt(s) left)", "error")
        logger.warning("Failed login for %s from %s", username, rl_key)

    show_2fa = session.get("show_2fa_setup")
    if request.method == "GET":
        session.pop("show_2fa_setup", None)
    return render_template("login.html", show_2fa=show_2fa)

# ---------------------------------------------------------------------------
# Routes – OTP / 2FA
# ---------------------------------------------------------------------------
@app.route("/otp", methods=["GET", "POST"])
def otp():
    if "temp_user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        if not _validate_csrf(request.form.get("csrf_token", "")):
            abort(400)
        otp_code = request.form.get("otp", "").strip()
        if not otp_code.isdigit() or len(otp_code) != 6:
            flash("OTP must be a 6-digit number", "error")
            return render_template("otp.html")

        username = session["temp_user"]
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not user:
            session.pop("temp_user", None)
            return redirect(url_for("login"))

        totp = pyotp.TOTP(user["secret"])
        if totp.verify(otp_code, valid_window=1):
            session["user"] = user["username"]
            session.pop("temp_user", None)
            db.execute(
                "UPDATE users SET last_login = datetime('now') WHERE username = ?",
                (user["username"],),
            )
            db.commit()
            logger.info("Successful 2FA login for %s", user["username"])
            flash("Login successful", "success")
            return redirect(url_for("home"))

        flash("Invalid OTP code. Please try again.", "error")
        logger.warning("Invalid OTP attempt for %s", username)

    return render_template("otp.html")

# ---------------------------------------------------------------------------
# Routes – Logout
# ---------------------------------------------------------------------------
@app.route("/logout")
def logout():
    user = session.get("user")
    session.clear()
    if user:
        logger.info("User logged out: %s", user)
    flash("You have been logged out", "success")
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

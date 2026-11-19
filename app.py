#!/usr/bin/env python3
"""
Secure Login System  -  Thiranex Cyber Security Internship, Task 4
==================================================================
Features (from the task card)
  * Registration + login with HASHED passwords (Argon2id)          passwords.py
  * Input validation + protection from SQL injection                validators.py, db.py
  * Session management with logout                                  server-side sessions
  * Optional Two-Factor Authentication (TOTP)                       totp.py
Extra hardening: CSRF tokens, account lock-out, no user enumeration on login,
security headers, session timeouts, audit log, safe cookies.

Run (development):   python app.py        -> http://127.0.0.1:5000
For real deployment: use HTTPS (reverse proxy), set SECRET_KEY and COOKIE_SECURE=1,
and run with a production server such as gunicorn - NOT the Flask dev server.
"""
import hashlib
import os
import secrets
import sqlite3
import time
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)

import db
import passwords
import totp
import validators

MAX_FAILED = 5               # wrong attempts before lock-out
LOCK_SECONDS = 15 * 60
IDLE_TIMEOUT = 15 * 60       # log out after 15 min of inactivity
ABSOLUTE_TIMEOUT = 8 * 3600  # ...and never keep a session longer than 8 h
PENDING_2FA_SECONDS = 5 * 60
GENERIC_LOGIN_ERROR = "Invalid credentials, or the account is temporarily locked."


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("DATABASE", "secure_login.db"),
        SESSION_COOKIE_HTTPONLY=True,          # JavaScript cannot read the cookie (XSS)
        SESSION_COOKIE_SAMESITE="Lax",         # browser will not send it on cross-site POSTs
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",  # HTTPS only
        MAX_CONTENT_LENGTH=16 * 1024,          # reject huge requests
        CLOCK=time.time,                       # injectable so tests can move time
    )
    if config:
        app.config.update(config)
    if "SECRET_KEY" not in os.environ and not (config and "SECRET_KEY" in config):
        app.logger.warning("SECRET_KEY not set: using a random key (sessions reset on restart).")

    app.teardown_appcontext(db.close_db)
    with app.app_context():
        db.init_db()
    # Verified when the username does not exist, so "unknown user" and "wrong
    # password" take about the same time (prevents timing-based user enumeration).
    app.config["DUMMY_HASH"] = passwords.hash_password(secrets.token_urlsafe(16))

    def now():
        return app.config["CLOCK"]()

    def audit(event, username=None):
        db.execute("INSERT INTO audit_log (ts, username, event, ip) VALUES (?, ?, ?, ?)",
                   (now(), username, event, request.remote_addr))

    # ------------------------------------------------------------------ session
    def start_session(user):
        """Create a NEW server-side session (also defeats session fixation)."""
        t = now()
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
                   (user["id"],))
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (t,))
        session.clear()
        session["csrf"] = secrets.token_urlsafe(32)
        token = secrets.token_urlsafe(32)
        db.execute("INSERT INTO sessions (token_hash, user_id, created_at, last_seen, expires_at) "
                   "VALUES (?, ?, ?, ?, ?)",
                   (sha256(token), user["id"], t, t, t + ABSOLUTE_TIMEOUT))
        session["sid"] = token          # only a random token; the DB decides if it is valid
        audit("login_success", user["username"])

    def register_failure(user):
        failed = user["failed_attempts"] + 1
        if failed >= MAX_FAILED:
            db.execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                       (now() + LOCK_SECONDS, user["id"]))
            audit("account_locked", user["username"])
        else:
            db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed, user["id"]))

    @app.before_request
    def load_session_and_check_csrf():
        g.user = None
        token = session.get("sid")
        if token:
            row = db.query_one("SELECT * FROM sessions WHERE token_hash = ?", (sha256(token),))
            t = now()
            if row and t < row["expires_at"] and t - row["last_seen"] < IDLE_TIMEOUT:
                g.user = db.query_one("SELECT * FROM users WHERE id = ?", (row["user_id"],))
                db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
                           (t, row["token_hash"]))
            else:
                if row:
                    db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
                session.pop("sid", None)
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method == "POST":       # CSRF: the form must carry our secret token
            sent = request.form.get("csrf_token", "").encode()
            if not secrets.compare_digest(sent, session["csrf"].encode()):
                abort(400, "Invalid or missing CSRF token.")

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.context_processor
    def template_globals():
        return {"csrf_token": lambda: session.get("csrf", ""), "current_user": g.get("user")}

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    # ------------------------------------------------------------------- pages
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html", username="", email="")
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        pw, confirm = request.form.get("password", ""), request.form.get("confirm", "")
        errors = (validators.validate_username(username) + validators.validate_email(email)
                  + validators.validate_password(pw, username))
        if pw != confirm:
            errors.append("Passwords do not match.")
        if not errors:
            try:
                db.execute(
                    "INSERT INTO users (username, username_lower, email, email_lower, "
                    "password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (username, username.lower(), email, email.lower(),
                     passwords.hash_password(pw), now()))
                audit("register", username)
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                errors.append("That username or email is already registered.")
        for e in errors:
            flash(e, "error")
        return render_template("register.html", username=username, email=email), 400

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")
        username = request.form.get("username", "").strip()[:64]
        pw = request.form.get("password", "")[:validators.MAX_PW + 1]
        user = None
        if validators.USERNAME_RE.fullmatch(username):     # allow-list before touching the DB
            user = db.query_one("SELECT * FROM users WHERE username_lower = ?", (username.lower(),))
        locked = bool(user and user["locked_until"] > now())
        ok = passwords.verify_password(user["password_hash"] if user else app.config["DUMMY_HASH"], pw)
        if user and ok and not locked:
            if passwords.needs_rehash(user["password_hash"]):      # upgrade old hash parameters
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                           (passwords.hash_password(pw), user["id"]))
            if user["totp_enabled"]:
                session.clear()
                session["csrf"] = secrets.token_urlsafe(32)
                session["pending"] = {"uid": user["id"], "exp": now() + PENDING_2FA_SECONDS}
                return redirect(url_for("verify_2fa"))
            start_session(user)
            return redirect(url_for("dashboard"))
        if user and not locked:
            register_failure(user)
        audit("login_failed", username if user else None)
        flash(GENERIC_LOGIN_ERROR, "error")        # identical message in every failure case
        return render_template("login.html", username=username), 401

    @app.route("/2fa/verify", methods=["GET", "POST"])
    def verify_2fa():
        pending = session.get("pending")
        if not pending or now() > pending["exp"]:
            session.pop("pending", None)
            flash("Please log in again.", "error")
            return redirect(url_for("login"))
        if request.method == "GET":
            return render_template("twofa_verify.html")
        user = db.query_one("SELECT * FROM users WHERE id = ?", (pending["uid"],))
        if not user or user["locked_until"] > now():
            session.pop("pending", None)
            flash(GENERIC_LOGIN_ERROR, "error")
            return redirect(url_for("login"))
        code = request.form.get("code", "").strip().replace(" ", "")
        step = totp.verify(user["totp_secret"], code, now(), last_step=user["totp_last_step"])
        if step is None:
            register_failure(user)     # wrong codes count towards the same lock-out
            audit("2fa_failed", user["username"])
            flash("Invalid authentication code.", "error")
            return render_template("twofa_verify.html"), 401
        db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
        start_session(user)
        return redirect(url_for("dashboard"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/logout", methods=["POST"])        # POST + CSRF: a link/image cannot log you out
    def logout():
        token = session.get("sid")
        if token:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (sha256(token),))
        if g.user:
            audit("logout", g.user["username"])
        session.clear()
        session["csrf"] = secrets.token_urlsafe(32)
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/2fa/setup", methods=["GET", "POST"])
    @login_required
    def setup_2fa():
        user = g.user
        if user["totp_enabled"]:
            flash("Two-factor authentication is already enabled.", "success")
            return redirect(url_for("dashboard"))
        secret = user["totp_secret"]
        if not secret:
            secret = totp.new_secret()
            db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
        if request.method == "POST":
            code = request.form.get("code", "").strip().replace(" ", "")
            step = totp.verify(secret, code, now())
            if step is None:
                flash("That code is not valid. Check the app and try again.", "error")
            else:
                db.execute("UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?",
                           (step, user["id"]))
                audit("2fa_enabled", user["username"])
                flash("Two-factor authentication is now ON.", "success")
                return redirect(url_for("dashboard"))
        return render_template("twofa_setup.html", secret=secret,
                               uri=totp.provisioning_uri(secret, user["username"]))

    @app.route("/2fa/disable", methods=["POST"])
    @login_required
    def disable_2fa():
        if passwords.verify_password(g.user["password_hash"], request.form.get("password", "")):
            db.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL, "
                       "totp_last_step = 0 WHERE id = ?", (g.user["id"],))
            audit("2fa_disabled", g.user["username"])
            flash("Two-factor authentication turned off.", "success")
        else:
            flash("Wrong password - 2FA was NOT changed.", "error")
        return redirect(url_for("dashboard"))

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    def error_page(err):
        return render_template("error.html", code=err.code, message=err.name), err.code

    return app


if __name__ == "__main__":
    # debug=False on purpose: Flask's debugger would allow remote code execution.
    create_app().run(host="127.0.0.1", port=5000, debug=False)

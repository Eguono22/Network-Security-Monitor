"""Password authentication, signed sessions, CSRF, and persistent login throttling."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from datetime import timedelta

from flask import g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

ROLES = {"viewer", "analyst", "admin"}
# A valid expensive hash ensures unknown users take the same verification path.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32))


def auth_disabled(app) -> bool:
    if os.getenv("NSM_AUTH_MODE", "password") != "disabled":
        return False
    return app.testing or (
        request.remote_addr in {"127.0.0.1", "::1"}
        and os.getenv("NSM_ENV") != "production"
        and not (os.getenv("VERCEL") or os.getenv("VERCEL_ENV"))
    )


def load_users() -> dict:
    path = os.getenv("NSM_USERS_FILE", "")
    raw = os.getenv("NSM_USERS_JSON", "")
    if not path and not raw:
        raise ValueError("Authentication is not configured.")
    users = json.loads(Path(path).read_text(encoding="utf-8") if path else raw)
    if not isinstance(users, dict) or not users:
        raise ValueError("No user accounts configured.")
    for name, account in users.items():
        if not isinstance(name, str) or not isinstance(account, dict) or account.get("role") not in ROLES:
            raise ValueError("Invalid user account configuration.")
        password_hash = account.get("password_hash")
        if not isinstance(password_hash, str) or not password_hash.startswith(("scrypt:", "pbkdf2:")):
            raise ValueError("User accounts require supported password hashes.")
    return users


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def session_version(account: dict) -> str:
    return hashlib.sha256((account["password_hash"] + account["role"]).encode()).hexdigest()


def throttle_login(username: str) -> bool:
    """Atomically count attempts for an account and client; deny above budget."""
    from .postgres import postgres_enabled, connect
    keys = [hashlib.sha256(value.encode()).hexdigest() for value in (
        "user:" + username.lower(), "client:" + (request.remote_addr or "unknown"),
    )]
    now = time.time()
    if postgres_enabled():
        with connect() as conn:
            conn.execute("DELETE FROM auth_attempts WHERE started_at < %s", (now - 86400,))
            counts = []
            for key in sorted(keys):
                row = conn.execute("""
                    INSERT INTO auth_attempts (key, attempts, started_at) VALUES (%s, 1, %s)
                    ON CONFLICT (key) DO UPDATE SET
                      attempts = CASE WHEN auth_attempts.started_at < %s THEN 1 ELSE auth_attempts.attempts + 1 END,
                      started_at = CASE WHEN auth_attempts.started_at < %s THEN %s ELSE auth_attempts.started_at END
                    RETURNING attempts
                """, (key, now, now - 900, now - 900, now)).fetchone()
                counts.append(row["attempts"])
        return counts[0] <= 20 and counts[1] <= 20
    path = Path(os.getenv("NSM_AUTH_STATE_FILE", ".tmp/auth-attempts.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=10) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY, count INTEGER, started REAL)")
        conn.execute("BEGIN IMMEDIATE")
        counts = []
        for key in keys:
            row = conn.execute("SELECT count, started FROM attempts WHERE key = ?", (key,)).fetchone()
            count, started = (row[0] + 1, row[1]) if row and row[1] > now - 900 else (1, now)
            conn.execute("INSERT OR REPLACE INTO attempts VALUES (?, ?, ?)", (key, count, started))
            counts.append(count)
        conn.execute("DELETE FROM attempts WHERE started < ?", (now - 86400,))
    return all(count <= 20 for count in counts)


def install_auth(app) -> None:
    from .config import Config
    Config()  # Load host .env before configuring the session signing key.
    app.config.update(
        SECRET_KEY=os.getenv("NSM_SECRET_KEY"),
        SESSION_COOKIE_NAME="sentinelnet_session",
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("NSM_COOKIE_SECURE", "true").lower() != "false",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.context_processor
    def auth_context():
        return {"signed_in_user": getattr(g, "user", None), "authentication_enabled": not auth_disabled(app)}

    @app.before_request
    def protect_request():
        g.user = None
        if request.endpoint in {"health", "ready", "static"}:
            return None
        if auth_disabled(app):
            g.auth_disabled = True
            return None
        g.auth_disabled = False
        try:
            secret = app.config.get("SECRET_KEY") or ""
            if len(secret) < 32:
                raise ValueError("A session signing key of at least 32 characters is required.")
            users = load_users()
        except (ValueError, OSError):
            return jsonify(error="authentication_unconfigured", message="Configure a signing key and user accounts before serving this app."), 503
        name = session.get("username", "")
        account = users.get(name)
        if account and hmac.compare_digest(session.get("version", ""), session_version(account)):
            g.user = {"username": name, "role": account["role"]}
        if request.endpoint != "login" and not g.user:
            if request.path.startswith("/api/"):
                return jsonify(error="authentication_required"), 401
            return redirect(url_for("login"))
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not token or not hmac.compare_digest(token, session.get("csrf", "")):
                return jsonify(error="invalid_csrf_token", message="Reload the page and try again."), 400

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if auth_disabled(app):
            return redirect(url_for("root"))
        if g.user:
            return redirect(url_for("root"))
        error = ""
        status = 200
        if request.method == "POST":
            username = request.form.get("username", "").strip()[:128]
            password = request.form.get("password", "")
            try:
                permitted = throttle_login(username)
            except Exception:
                app.logger.error("Login throttling store is unavailable")
                return render_template("login.html", error="Sign-in is temporarily unavailable."), 503
            if not permitted:
                return render_template("login.html", error="Too many sign-in attempts. Try again in 15 minutes."), 429
            account = load_users().get(username)
            valid = check_password_hash(account["password_hash"] if account else _DUMMY_HASH, password)
            if account and valid:
                session.clear()
                session.permanent = True
                session["username"] = username
                session["version"] = session_version(account)
                csrf_token()
                return redirect(url_for("root"), code=303)
            error = "Invalid username or password."
            status = 401
        return render_template("login.html", error=error), status

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"), code=303)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

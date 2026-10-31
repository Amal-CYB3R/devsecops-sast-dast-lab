import os
import re
import sqlite3
import subprocess
import ipaddress

from flask import Flask, request, session, abort, render_template_string
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

csrf = CSRFProtect(app)

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required")

if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD environment variable is required")

app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

DB = os.environ.get("DB_PATH", "users.db")


def get_db():
    return sqlite3.connect(DB)


def init_db():
    with get_db() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
            """
        )

        con.execute(
            """
            INSERT OR IGNORE INTO users (username, password)
            VALUES (?, ?)
            """,
            ("admin", generate_password_hash(ADMIN_PASSWORD)),
        )
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )

    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    response.headers["Cache-Control"] = "no-store"

    return response


@app.route("/")
def home():
    return render_template_string(
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>DevSecOps Security Lab</title>
        </head>
        <body>
            <h1>DevSecOps Security Lab - Fixed Version</h1>

            <ul>
                <li><a href="/search?q=test">Search</a></li>
                <li><a href="/ping?host=127.0.0.1">Ping</a></li>
                <li><a href="/user/1">Admin profile</a></li>
            </ul>

            <form action="/login" method="post">
                <input type="hidden" name="csrf_token"
                       value="{{ csrf_token() }}">

                <label>
                    Username:
                    <input name="username" autocomplete="username" required>
                </label>
                <br>

                <label>
                    Password:
                    <input name="password" type="password"
                           autocomplete="current-password" required>
                </label>
                <br>

                <button type="submit">Login</button>
            </form>

            <form action="/logout" method="post">
                <input type="hidden" name="csrf_token"
                       value="{{ csrf_token() }}">
                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
        """
    )


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    with get_db() as con:
        row = con.execute(
            "SELECT id, password FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if row and check_password_hash(row[1], password):
        session.clear()
        session["user_id"] = row[0]
        return "Welcome", 200

    return "Invalid credentials", 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return "Logged out", 200


@app.route("/search")
def search():
    term = request.args.get("q", "")
    return "<h1>Results for " + str(escape(term)) + "</h1>"


def is_valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if len(host) > 253:
        return False

    hostname_pattern = (
        r"(?=^.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
        r"(?:\."
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    )

    return bool(re.fullmatch(hostname_pattern, host))


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    if not is_valid_host(host):
        return "Invalid host", 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "--", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        output = result.stdout + result.stderr
        return "<pre>" + str(escape(output)) + "</pre>"

    except subprocess.TimeoutExpired:
        return "Ping timed out", 504

    except OSError:
        app.logger.exception("Ping command failed")
        return "Ping command failed", 500


@app.route("/user/<int:uid>")
def user(uid):
    if "user_id" not in session:
        abort(401)

    if session["user_id"] != uid:
        abort(403)

    with get_db() as con:
        row = con.execute(
            "SELECT id, username FROM users WHERE id = ?",
            (uid,),
        ).fetchone()

    if row is None:
        abort(404)

    return (
        "<p>User ID: "
        + str(row[0])
        + "</p><p>Username: "
        + str(escape(row[1]))
        + "</p>"
    )


@app.errorhandler(400)
def bad_request(_error):
    return "Bad request", 400


@app.errorhandler(401)
def unauthorized(_error):
    return "Authentication required", 401


@app.errorhandler(403)
def forbidden(_error):
    return "Access denied", 403


@app.errorhandler(404)
def not_found(_error):
    return "Resource not found", 404


# Initialize the database when the application module loads.
init_db()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )

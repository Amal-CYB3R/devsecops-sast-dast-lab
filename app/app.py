import sqlite3, hashlib, subprocess, os
from flask import Flask, request,session
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required")
DB = "users.db"

def get_db():
    return sqlite3.connect(DB)

def init_db():
    con = get_db()
    con.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    pw = generate_password_hash("password123")
    con.execute("INSERT OR IGNORE INTO users(id, username, password) VALUES (1,'admin',?)", (pw,))
    con.commit()

@app.route("/")
def home():
    return """
    <h1>Intentionally vulnerable demo app</h1>
    <ul>
      <li><a href="/search?q=test">Search</a></li>
      <li><a href="/ping?host=127.0.0.1">Ping</a></li>
      <li><a href="/user/1">User profile</a></li>
    </ul>
    <form action="/login" method="post">
      <input name="username"> <input name="password" type="password">
      <button>Login</button>
    </form>
    """

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    hashed = hashlib.md5(p.encode()).hexdigest()

    q = "SELECT * FROM users WHERE username=?"
    row = get_db().execute(q, (u,)).fetchone()

    if row and check_password_hash(row[2], p):
        session["user_id"] = row[0]
        return "Welcome"

    return "Invalid credentials"

@app.route("/search")
def search():
    term = request.args.get("q", "")
    return "<h1>Results for " + str(escape(term)) + "</h1>"

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Ping timed out", 400

@app.route("/user/<int:uid>")
def user(uid):
    if "user_id" not in session:
        return "Please log in first", 401

    if session["user_id"] != uid:
        return "Access denied", 403

    row = get_db().execute(
        "SELECT id, username FROM users WHERE id=?",
        (uid,)
    ).fetchone()

    return str(row) if row else ("User not found", 404)
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)

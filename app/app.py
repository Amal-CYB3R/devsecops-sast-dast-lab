import sqlite3, hashlib, subprocess
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "fake-demo-secret-123"      # VULN 1: hard-coded secret (A02)
DB = "users.db"

def get_db():
    return sqlite3.connect(DB)

def init_db():
    con = get_db()
    con.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    pw = hashlib.md5(b"password123").hexdigest()
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
    hashed = hashlib.md5(p.encode()).hexdigest()                       # VULN 2: weak hash (A02)
    q = "SELECT * FROM users WHERE username='" + u + "' AND password='" + hashed + "'"  # VULN 3: SQL injection (A03)
    row = get_db().execute(q).fetchone()
    return "Welcome" if row else "Invalid credentials"

@app.route("/search")
def search():
    term = request.args.get("q", "")
    return "<h1>Results for " + term + "</h1>"                          # VULN 4: reflected XSS (A03)

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.getoutput("ping -c 1 " + host)                    # VULN 5: command injection (A03)

@app.route("/user/<int:uid>")
def user(uid):                                                          # VULN 6: no access control / IDOR (A01)
    row = get_db().execute("SELECT id, username FROM users WHERE id=" + str(uid)).fetchone()
    return str(row)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)                      # VULN 7: debug mode on (A05)

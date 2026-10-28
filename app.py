import os, json, time, hmac, hashlib, secrets, sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB = os.environ.get("DB_PATH", "/tmp/montroy.db")
SECRET = os.environ.get("AUTH_SECRET", "montroy-secret-trocar").encode()

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE COLLATE NOCASE,
        salt TEXT, pw TEXT, fp TEXT,
        created REAL)""")
    c.commit()
    # conta padrao Montroy
    if not c.execute("SELECT 1 FROM users WHERE username='Montroy'").fetchone():
        salt = secrets.token_hex(8)
        c.execute("INSERT INTO users(username,salt,pw,fp,created) VALUES(?,?,?,?,?)",
                  ("Montroy", salt, _hash("montroy123", salt), "Google|seed-montroy", time.time()))
        c.commit()
    c.close()

def _hash(p, salt):
    return hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 120000).hex()

def _token(uid):
    exp = int(time.time()) + 60 * 60 * 24 * 365
    body = f"{uid}.{exp}"
    sig = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
    return f"MTR{body}.{sig}"

def _check(tok):
    try:
        t = tok[3:]
        uid, exp, sig = t.split(".")
        good = hmac.new(SECRET, f"{uid}.{exp}".encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, good) and int(exp) > time.time():
            return int(uid)
    except Exception:
        pass
    return None

def _me(row):
    return {
        "id": row["id"], "username": row["username"], "bricksBalance": 1000,
        "avatarID": str(row["id"]), "membershipType": "plus",
        "description": "Conta Montroy",
        "signature": "[b][c][FFD319]\u24cb",
    }

@app.get("/")
def home():
    return "Montroy auth online"

@app.post("/v1/mobile/register")
def register():
    d = request.get_json(silent=True) or {}
    u = (d.get("username") or "").strip()
    p = d.get("password") or ""
    fp = d.get("fingerprint") or ""
    if len(u) < 3 or len(u) > 20 or not u.replace("_", "").isalnum():
        return jsonify(success=False, error="Nome invalido (3-20, letras/numeros)"), 400
    if len(p) < 4:
        return jsonify(success=False, error="Senha muito curta (min 4)"), 400
    c = db()
    if c.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
        c.close()
        return jsonify(success=False, error="Nome ja existe"), 409
    salt = secrets.token_hex(8)
    cur = c.execute("INSERT INTO users(username,salt,pw,fp,created) VALUES(?,?,?,?,?)",
                    (u, salt, _hash(p, salt), fp, time.time()))
    c.commit()
    uid = cur.lastrowid
    c.close()
    return jsonify(success=True, token=_token(uid))

@app.post("/v1/mobile/login")
def login():
    d = request.get_json(silent=True) or {}
    u = (d.get("username") or "").strip()
    p = d.get("password") or ""
    c = db()
    row = c.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    c.close()
    if not row or not hmac.compare_digest(row["pw"], _hash(p, row["salt"])):
        return jsonify(success=False, error="Usuario ou senha incorretos"), 401
    return jsonify(success=True, token=_token(row["id"]))

@app.get("/api/users/me")
def me():
    h = request.headers.get("Authorization", "")
    uid = _check(h.replace("Bearer ", "")) if h.startswith("Bearer ") else None
    if uid is None:
        return jsonify(error="unauthorized"), 401
    c = db()
    row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    c.close()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(_me(row))

init()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

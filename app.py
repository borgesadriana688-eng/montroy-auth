import os, json, time, hmac, hashlib, secrets, base64, urllib.request

from flask import Flask, request, jsonify

app = Flask(__name__)

GH_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GH_REPO = os.environ.get("GH_REPO", "borgesadriana688-eng/montroy-auth")
GH_PATH = "contas.json"
SECRET = os.environ.get("AUTH_SECRET", "montroy-secret").encode()
LOCAL = "/tmp/contas.json"

_contas = {}


def _gh_headers():
    return {
        "Authorization": "token " + GH_TOKEN,
        "Accept": "application/vnd.github+json",
        "User-Agent": "montroy-auth",
    }


def _gh_get():
    if not GH_TOKEN:
        return None
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{GH_REPO}/contents/{GH_PATH}",
            headers=_gh_headers(),
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        return json.loads(base64.b64decode(data["content"]).decode()), data.get("sha")
    except Exception as e:
        print("gh get:", e)
        return None


def _gh_put(text, sha):
    if not GH_TOKEN:
        return
    try:
        body = {
            "message": "contas montroy " + time.strftime("%Y-%m-%d %H:%M"),
            "content": base64.b64encode(text.encode()).decode(),
            "branch": "main",
        }
        if sha:
            body["sha"] = sha
        req = urllib.request.Request(
            f"https://api.github.com/repos/{GH_REPO}/contents/{GH_PATH}",
            data=json.dumps(body).encode(),
            headers=_gh_headers(),
            method="PUT",
        )
        urllib.request.urlopen(req, timeout=20).read()
    except Exception as e:
        print("gh put:", e)


_sha = None


def load():
    global _contas, _sha
    got = _gh_get()
    if isinstance(got, tuple):
        data, _sha = got
        if isinstance(data, dict):
            _contas = data
            print("contas carregadas:", len(_contas))
            return
    if os.path.exists(LOCAL):
        try:
            _contas = json.load(open(LOCAL))
        except Exception:
            _contas = {}
    if not _contas:
        _contas = _seed()
        save()


def save():
    global _sha
    txt = json.dumps(_contas, indent=1, ensure_ascii=False)
    open(LOCAL, "w").write(txt)
    _gh_put(txt, _sha)
    got = _gh_get()
    if isinstance(got, tuple):
        _sha = got[1]


def _hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120000).hex()


def _token(uid):
    exp = int(time.time()) + 60 * 60 * 24 * 365
    body = f"{uid}.{exp}"
    sig = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
    return f"MTR{body}.{sig}"


def _check(tok):
    try:
        uid, exp, sig = tok[3:].split(".")
        good = hmac.new(SECRET, f"{uid}.{exp}".encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, good) and int(exp) > time.time():
            return int(uid)
    except Exception:
        pass
    return None


def _me(c):
    return {
        "id": c["id"],
        "username": c["username"],
        "bricksBalance": 1000,
        "avatarID": str(c["id"]),
        "membershipType": "plus",
        "description": "Conta Montroy",
        "signature": "[b][c][FFD319]\u24cb",
    }


def _seed():
    salt = secrets.token_hex(8)
    return {
        "1": {
            "id": 1,
            "username": "Montroy",
            "salt": salt,
            "pw": _hash("montroy123", salt),
            "fp": "Google|seed",
            "created": int(time.time()),
        }
    }


def _next_id():
    return max((int(k) for k in _contas.keys()), default=0) + 1


@app.get("/")
def home():
    return f"Montroy auth online ({len(_contas)} contas)"


@app.get("/v1/contas")
def listar():
    # contagem publica, sem expor senhas
    return jsonify(total=len(_contas))


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
    for c in _contas.values():
        if c["username"].lower() == u.lower():
            return jsonify(success=False, error="Nome ja existe"), 409
    uid = _next_id()
    salt = secrets.token_hex(8)
    _contas[str(uid)] = {
        "id": uid,
        "username": u,
        "salt": salt,
        "pw": _hash(p, salt),
        "fp": fp,
        "created": int(time.time()),
    }
    save()
    return jsonify(success=True, token=_token(uid), uid=uid)


@app.post("/v1/mobile/login")
def login():
    d = request.get_json(silent=True) or {}
    u = (d.get("username") or "").strip().lower()
    p = d.get("password") or ""
    for c in _contas.values():
        if c["username"].lower() == u:
            if hmac.compare_digest(c["pw"], _hash(p, c["salt"])):
                return jsonify(success=True, token=_token(c["id"]), uid=c["id"])
            return jsonify(success=False, error="Senha incorreta"), 401
    return jsonify(success=False, error="Usuario nao existe"), 404


@app.get("/api/users/me")
def me():
    h = request.headers.get("Authorization", "")
    uid = _check(h.replace("Bearer ", "")) if h.startswith("Bearer ") else None
    if uid is None:
        return jsonify(error="unauthorized"), 401
    c = _contas.get(str(uid))
    if not c:
        return jsonify(error="not found"), 404
    return jsonify(_me(c))


@app.post("/api/places/join")
def join_place():
    d = request.get_json(silent=True) or {}
    if not d.get("placeID"):
        return jsonify(success=False, error="placeID ausente"), 400
    return jsonify(success=True, token="MTRJOIN." + _token(1)[3:])


load()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

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


_codigos = {}
GameKey = os.environ.get("GAME_KEY", "montroy-game-key")


# ================= PAINEL SECRETO (comanda o jogo) =================
import datetime as _dt

_bloqueios = set()
_sessoes = set()
_fila = []
_hist = []


def _ip():
    return (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()


PAINEL_LOGIN = """<!DOCTYPE html><html lang=pt-BR><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Montroy</title><style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0512;color:#fff;font-family:system-ui}
.box{width:min(92vw,340px);background:#150a26;border:1px solid #4b2a8a;border-radius:14px;padding:20px}
h1{margin:0 0 14px;font-size:18px;text-align:center;color:#ffd319;letter-spacing:2px}
input{width:100%;padding:12px;margin-bottom:10px;border-radius:9px;border:1px solid #4b2a8a;background:#0d0618;color:#fff}
button{width:100%;padding:12px;border:0;border-radius:9px;background:#6b2fd6;color:#fff;font-weight:600}
.m{min-height:16px;text-align:center;font-size:12px;color:#ff6b81;margin-top:8px}
</style></head><body><div class=box><h1>MONTROY</h1>
<form method=post action=/painel/login><input name=usuario placeholder=Usuario autocomplete=off>
<input name=senha type=password placeholder=Senha><button>Entrar</button></form>
<div class=m>__MSG__</div></div></body></html>"""


PAINEL = """<!DOCTYPE html><html lang=pt-BR><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Painel Montroy</title><style>
*{box-sizing:border-box}body{margin:0;background:#0a0512;color:#e9e2ff;font-family:ui-monospace,monospace}
header{background:#6b2fd6;padding:12px 16px;font-weight:700;color:#fff;letter-spacing:1px}
.wrap{padding:14px;display:grid;gap:12px;max-width:820px;margin:0 auto}
input,select,button{font-family:inherit;font-size:14px;padding:10px;border-radius:8px;border:1px solid #4b2a8a;background:#150a26;color:#fff}
button{background:#6b2fd6;border:0;font-weight:600;cursor:pointer}
.row{display:flex;gap:8px}.row input{flex:1}
.card{background:#150a26;border:1px solid #33195c;border-radius:12px;padding:12px}
h3{margin:0 0 8px;font-size:13px;color:#b79bff;text-transform:uppercase;letter-spacing:1px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{background:#241141;border:1px solid #3f2270;border-radius:999px;padding:6px 10px;font-size:12px;cursor:pointer}
.chip:hover{background:#3b1d6b}
pre{white-space:pre-wrap;margin:0;font-size:12px;color:#9be564;max-height:240px;overflow:auto}
.alvo{color:#ffd319}
</style></head><body>
<header>MONTROY // CONSOLE</header>
<div class=wrap>
<div class=card"><h3>Comando</h3>
<div class=row><input id=cmd placeholder=":fly  ou  :kick Fulano"><button onclick="enviar()">Executar</button></div>
<div style="margin-top:8px" class=chips id=chips></div></div>
<div class=card"><h3>Alvo atual</h3><div class=row><input id=alvo placeholder="nome do jogador"><button onclick="usarAlvo()">Usar nos poderes</button></div></div>
<div class=card"><h3>Fila / historico</h3><pre id=log>carregando...</pre></div>
</div>
<script>
var alvo='';
function chips(list){var c=document.getElementById('chips');
 list.forEach(function(x){var d=document.createElement('div');d.className='chip';d.textContent=x;
 d.onclick=function(){var i=document.getElementById('cmd');i.value=x;};c.appendChild(d);});}
chips([':fly',':unfly',':noclip',':clip',':god',':ungod',':heal',':invis',':vis',':speed 200',':ws 200',':jp 200',
':big',':small',':normal',':bring',':to',':tp',':freeze',':thaw',':jail',':unjail',':blind',':unblind',':explode',
':rocket',':fling',':control',':view',':kick',':ban',':unban',':permaban',':mute',':unmute',':crash',':shutdown',
':respawn',':m',':h',':music',':stopMusic',':time day',':time night',':fog']);
function usarAlvo(){alvo=document.getElementById('alvo').value.trim();
 var i=document.getElementById('cmd');var v=i.value.trim();
 if(v.indexOf(' ')<=0){i.value=v+' '+alvo;}}
function enviar(){var i=document.getElementById('cmd');var c=i.value.trim();if(!c)return;
 fetch('/v1/comando',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd:c})})
 .then(function(r){return r.json()}).then(function(d){i.value='';ler();});}
function ler(){fetch('/painel/log').then(function(r){return r.json()}).then(function(d){
 document.getElementById('log').textContent=d.texto;});}
ler();setInterval(ler,2500);
</script></body></html>"""


@app.get("/painel")
def painel_entrada():
    if _ip() in _bloqueios:
        return "BLOQUEADO", 403
    if request.cookies.get("sess") in _sessoes:
        return PAINEL
    return PAINEL_LOGIN.replace("__MSG__", "")


@app.post("/painel/login")
def painel_login():
    ip = _ip()
    if ip in _bloqueios:
        return "BLOQUEADO", 403
    u = (request.form.get("usuario") or "").strip()
    p = (request.form.get("senha") or "").strip()
    if u == "campanha1233" and p == "997169332":
        tok = secrets.token_hex(16)
        _sessoes.add(tok)
        resp = app.make_response(PAINEL)
        resp.set_cookie("sess", tok, httponly=True, samesite="Lax")
        return resp
    _bloqueios.add(ip)
    return PAINEL_LOGIN.replace("__MSG__", "ACESSO BLOQUEADO"), 403


@app.post("/v1/comando")
def comando():
    if request.cookies.get("sess") not in _sessoes:
        return jsonify(error="nao autorizado"), 403
    d = request.get_json(silent=True) or {}
    c = (d.get("cmd") or "").strip()
    if not c.startswith(":"):
        return jsonify(error="comando invalido"), 400
    item = {"cmd": c, "ts": int(time.time()), "id": secrets.token_hex(6)}
    _fila.append(item)
    _hist.append(c)
    return jsonify(ok=True, item=item)


@app.get("/v1/comandos")
def comandos():
    # o jogo consulta esta rota e executa a fila
    tok = request.headers.get("X-Game-Key", "")
    if tok != GameKey:
        return jsonify(error="nao autorizado"), 403
    saida = list(_fila)
    _fila.clear()
    return jsonify(comandos=saida)


@app.get("/painel/log")
def painel_log():
    if request.cookies.get("sess") not in _sessoes:
        return jsonify(texto="nao autorizado"), 403
    pend = ", ".join(i["cmd"] for i in _fila) if _fila else "vazia"
    hist = "\n".join(_hist[-20:]) if _hist else "nenhum"
    return jsonify(texto="Fila: " + pend + "\n\nUltimos comandos:\n" + hist)


@app.get("/v1/users/<int:uid>")
def user_info(uid):
    c = _contas.get(str(uid))
    if not c:
        return jsonify(error="not found"), 404
    dt = _dt.datetime.utcfromtimestamp(c.get("created", 0)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return jsonify(
        id=c["id"], username=c["username"], description="Conta Montroy",
        signature="[b][c][FFD319]\u24cb", registeredAt=dt, createdAt=dt,
        netWorth=0, placeVisits=0, profileViews=0, forumPosts=0, playing=None,
        thumbnail={"url": "", "final": True},
    )



# ---------- pagina de login/cadastro (abre no navegador a partir do app) ----------
PAGINA = """<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Montroy - Entrar</title><style>
*{box-sizing:border-box;font-family:system-ui,sans-serif}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:linear-gradient(160deg,#1a0b2e,#2d1152 60%,#12081f);color:#fff}
.card{width:min(92vw,380px);background:rgba(12,6,24,.92);border:1px solid #6b3fd4;border-radius:16px;padding:22px}
h1{margin:0 0 4px;font-size:26px;letter-spacing:2px;text-align:center;color:#ffd319}
p.sub{margin:0 0 18px;text-align:center;font-size:12px;color:#b7a8d6}
.tabs{display:flex;gap:8px;margin-bottom:14px}
.tab{flex:1;padding:10px;border-radius:10px;border:1px solid #6b3fd4;background:transparent;color:#fff;font-size:14px}
.tab.on{background:#6b3fd4}
input{width:100%;padding:12px;margin-bottom:10px;border-radius:10px;border:1px solid #4a2f8f;background:#170c2b;color:#fff;font-size:15px}
button.go{width:100%;padding:13px;border:0;border-radius:10px;background:#7c3aed;color:#fff;font-size:16px;font-weight:600}
.msg{min-height:18px;font-size:13px;text-align:center;margin-top:10px;color:#ff8fa3}
</style></head><body>
<div class="card">
<h1>MONTROY</h1>
<p class="sub">Bem vindo ao montroy Server, desenvolvido por Brayan</p>
<div class="tabs"><button class="tab on" id="tLogin" onclick="modo('login')">Entrar</button>
<button class="tab" id="tReg" onclick="modo('register')">Criar conta</button></div>
<input id="u" placeholder="Nome de usuario" autocomplete="username">
<input id="p" type="password" placeholder="Senha" autocomplete="current-password">
<button class="go" id="btn" onclick="enviar()">Entrar</button>
<div class="msg" id="msg"></div>
</div>
<script>
var m='login';
var state=new URLSearchParams(location.search).get('state')||'';
function modo(x){m=x;document.getElementById('tLogin').className='tab'+(x=='login'?' on':'');
document.getElementById('tReg').className='tab'+(x=='register'?' on':'');
document.getElementById('btn').textContent=(x=='login'?'Entrar':'Criar conta');}
function enviar(){
 var u=document.getElementById('u').value.trim(),p=document.getElementById('p').value;
 var msg=document.getElementById('msg');
 if(u.length<3||p.length<4){msg.textContent='Usuario min 3 e senha min 4.';return;}
 msg.textContent='Conectando...';
 fetch('/v1/mobile/'+m,{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({username:u,password:p,fingerprint:'Google|web'})})
 .then(function(r){return r.json()})
 .then(function(d){
   if(d.success){msg.textContent='Tudo certo! Voltando para o app...';
     fetch('/auth/code',{method:'POST',headers:{'Content-Type':'application/json'},
       body:JSON.stringify({token:d.token,state:state})})
     .then(function(r){return r.json()})
     .then(function(c){location.href='polytoria://auth?code='+c.code+'&state='+encodeURIComponent(state)});}
   else{msg.textContent=d.error||'Falha';}
 })
 .catch(function(e){msg.textContent='Sem conexao';});
}
modo('login');
</script></body></html>"""


@app.get("/auth/mobile")
def auth_mobile():
    return PAGINA


@app.post("/auth/code")
def auth_code():
    d = request.get_json(silent=True) or {}
    tok = d.get("token") or ""
    uid = _check(tok) if tok.startswith("MTR") else None
    if uid is None:
        return jsonify(error="token invalido"), 401
    code = secrets.token_hex(16)
    _codigos[code] = {"uid": uid, "exp": time.time() + 300}
    return jsonify(code=code)


@app.post("/v1/mobile/token")
def mobile_token():
    d = request.get_json(silent=True) or {}
    code = d.get("code") or ""
    item = _codigos.pop(code, None)
    if not item or item["exp"] < time.time():
        return jsonify(success=False, error="code invalido"), 401
    return jsonify(success=True, token=_token(item["uid"]))


load()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

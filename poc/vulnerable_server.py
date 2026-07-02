#!/usr/bin/env python3
"""
vulnerable_server.py  -  a DELIBERATELY INSECURE JWT demo target for JWTweak.

A teaching/PoC target with a polished web UI (login -> dashboard -> admin
console) so proof-of-concept screenshots look like a real application being
exploited. It reproduces two classic JWT verification bugs ON PURPOSE.
NEVER copy this verification logic into anything real.

Run:
    pip install flask pyjwt cryptography
    python3 vulnerable_server.py            # http://127.0.0.1:5000

Browser PoC:
    1. Open http://127.0.0.1:5000  and click "Sign in" (demo creds prefilled).
    2. The dashboard shows your session token (role: user). "Admin Console"
       is denied.
    3. Forge an admin token with JWTweak, paste it into the "Session token"
       box, and open the Admin Console -> access granted.

curl PoC (unchanged):
    curl -s -X POST http://127.0.0.1:5000/login
    curl -s http://127.0.0.1:5000/admin -H "Authorization: Bearer <token>"

The vulnerabilities (both forgeable with JWTweak):
    1. alg:none is accepted           -> unsigned admin token is trusted.
    2. Algorithm confusion            -> the ONE public key is (mis)used as an
       (RS256 expected, HS256 given)     HMAC secret, so an HS256 token signed
                                          with the public key verifies.

SECURITY NOTE ON KEYS
    This script generates a throwaway RSA key pair on first run
    (private_key.pem / public_key.pem). Those keys protect nothing real, but
    they are still secret material and are gitignored - never commit private
    keys to a repository, even for a demo.
"""
import base64
import hashlib
import hmac
import json
import os

from flask import Flask, request, jsonify, make_response, redirect
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import jwt  # only used to MINT the legitimate token, not to verify it

app = Flask(__name__)


def _load_or_create_keys():
    if not os.path.exists("private_key.pem"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open("private_key.pem", "wb") as fh:
            fh.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        with open("public_key.pem", "wb") as fh:
            fh.write(key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
    with open("private_key.pem", "rb") as fh:
        priv = fh.read()
    with open("public_key.pem", "rb") as fh:
        pub = fh.read()
    return priv, pub


PRIVATE_KEY, PUBLIC_KEY_PEM = _load_or_create_keys()
PUBLIC_KEY = serialization.load_pem_public_key(PUBLIC_KEY_PEM)
_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
BRAND = "Aegis Cloud"
FLAG = "JWTweak{alg_confusion_and_none_win}"


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint_user_token():
    return jwt.encode({"sub": "alice", "name": "Alice Carter", "role": "user",
                       "iss": "aegis-cloud"}, PRIVATE_KEY, algorithm="RS256",
                      headers={"kid": "aegis-2024"})


# --------------------------------------------------------------------------- #
#  INSECURE verifier - the whole point of the demo. DO NOT REUSE.
# --------------------------------------------------------------------------- #
def insecure_verify(token):
    header_b64, payload_b64, sig_b64 = (token.split(".") + ["", "", ""])[:3]
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    alg = header.get("alg", "")
    signing_input = f"{header_b64}.{payload_b64}".encode()

    if alg.lower() == "none":                         # BUG #1
        return payload
    if alg in _HASHES:                                # BUG #2 (algorithm confusion)
        expected = base64.urlsafe_b64encode(
            hmac.new(PUBLIC_KEY_PEM, signing_input, _HASHES[alg]).digest()
        ).rstrip(b"=").decode()
        if hmac.compare_digest(expected, sig_b64):
            return payload
        raise ValueError("bad HMAC signature")
    if alg in ("RS256", "RS384", "RS512"):
        hash_alg = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(),
                    "RS512": hashes.SHA512()}[alg]
        PUBLIC_KEY.verify(b64url_decode(sig_b64), signing_input,
                          padding.PKCS1v15(), hash_alg)
        return payload
    raise ValueError(f"unsupported alg {alg}")


# --------------------------------------------------------------------------- #
#  UI
# --------------------------------------------------------------------------- #
CSS = """
:root{--bg:#0b0f19;--panel:#141a29;--panel2:#1b2334;--line:#263149;
--txt:#e7ecf5;--mut:#8a97b1;--accent:#4f8cff;--accent2:#7a5cff;
--ok:#22c98a;--bad:#ff5c72;--warn:#ffb020}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#1a2e4d 0,transparent 60%),
radial-gradient(900px 500px at -10% 10%,#191f33 0,transparent 55%),var(--bg);
color:var(--txt);font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:28px 20px 60px}
.nav{display:flex;align-items:center;justify-content:space-between;padding:8px 0 22px}
.brand{display:flex;align-items:center;gap:11px;font-weight:700;font-size:18px;letter-spacing:.2px}
.logo{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));
box-shadow:0 6px 18px rgba(79,140,255,.35)}
.pill{font-size:12px;color:var(--mut);border:1px solid var(--line);padding:4px 10px;border-radius:999px}
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);
border-radius:16px;padding:26px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
.card+.card{margin-top:18px}
h1{font-size:26px;margin:2px 0 6px}
h2{font-size:18px;margin:0 0 14px}
.sub{color:var(--mut);margin:0 0 20px}
label{display:block;font-size:13px;color:var(--mut);margin:14px 0 6px}
input,textarea{width:100%;background:#0d1220;border:1px solid var(--line);border-radius:10px;
color:var(--txt);padding:12px 14px;font-size:14px;font-family:inherit}
textarea{resize:vertical;min-height:96px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.btn{display:inline-flex;align-items:center;gap:8px;margin-top:18px;border:0;cursor:pointer;
background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;font-weight:600;font-size:15px;
padding:12px 20px;border-radius:10px;box-shadow:0 10px 24px rgba(79,140,255,.35)}
.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--txt);box-shadow:none}
.row{display:flex;gap:12px;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;gap:7px;padding:6px 12px;border-radius:999px;font-size:13px;font-weight:600}
.badge.user{background:rgba(255,176,32,.12);color:var(--warn);border:1px solid rgba(255,176,32,.3)}
.badge.admin{background:rgba(34,201,138,.12);color:var(--ok);border:1px solid rgba(34,201,138,.3)}
.kv{display:grid;grid-template-columns:120px 1fr;gap:8px 16px;margin:14px 0 2px}
.kv div:nth-child(odd){color:var(--mut)}
.tok{margin-top:8px;background:#0d1220;border:1px solid var(--line);border-radius:10px;padding:12px 14px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all;color:#9fd0ff}
.note{font-size:12.5px;color:var(--mut);margin-top:14px}
.denied{border-color:rgba(255,92,114,.4)}
.denied .ic{color:var(--bad)}
.granted{border-color:rgba(34,201,138,.4)}
.big-ic{font-size:44px;line-height:1}
.flag{margin-top:16px;background:#07120d;border:1px dashed rgba(34,201,138,.5);border-radius:10px;
padding:14px 16px;font-family:ui-monospace,Menlo,monospace;color:var(--ok);word-break:break-all}
.list{margin:10px 0 0;padding:0;list-style:none}
.list li{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--line);font-size:14px}
.list li:last-child{border-bottom:0}
.muted{color:var(--mut)}
a{color:var(--accent);text-decoration:none}
.footer{color:var(--mut);font-size:12px;text-align:center;margin-top:26px}
"""


def page(title, body):
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · {BRAND}</title><style>{CSS}</style></head><body><div class="wrap">
<div class="nav"><div class="brand"><span class="logo"></span>{BRAND}</div>
<span class="pill">Internal Console · demo</span></div>{body}
<div class="footer">{BRAND} — deliberately vulnerable demo for JWTweak. For education only.</div>
</div></body></html>"""


@app.get("/")
def index():
    body = """
<div class="card">
  <h1>Sign in to your console</h1>
  <p class="sub">Welcome back. Use your Aegis Cloud credentials to continue.</p>
  <form method="post" action="/login">
    <label>Email</label>
    <input name="email" value="alice@aegis.cloud" autocomplete="username">
    <label>Password</label>
    <input name="password" type="password" value="demo-password" autocomplete="current-password">
    <button class="btn" type="submit">Sign in &rarr;</button>
  </form>
  <p class="note">Demo credentials are prefilled. This environment is intentionally insecure.</p>
</div>"""
    return page("Sign in", body)


@app.post("/login")
def login():
    token = mint_user_token()
    # API/curl clients get JSON; browsers get a session cookie + redirect.
    accept = request.headers.get("Accept", "")
    if "application/json" in accept or request.args.get("format") == "json":
        return jsonify(access_token=token, token_type="Bearer", role="user")
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("session", token, samesite="Lax")
    return resp


@app.get("/public_key.pem")
def public_key():
    return app.response_class(PUBLIC_KEY_PEM, mimetype="application/x-pem-file")


def _current_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.cookies.get("session", "")


@app.get("/dashboard")
def dashboard():
    token = _current_token()
    if not token:
        return redirect("/")
    try:
        claims = insecure_verify(token)
    except Exception:
        try:
            claims = json.loads(b64url_decode(token.split(".")[1]))
        except Exception:
            claims = {}
    role = claims.get("role", "unknown")
    badge = ('<span class="badge admin">&#10003; admin</span>' if role == "admin"
             else f'<span class="badge user">&#9679; {role}</span>')
    body = f"""
<div class="card">
  <h2>Account overview</h2>
  <div class="kv">
    <div>Signed in as</div><div>{claims.get('name','—')} &lt;{claims.get('sub','—')}&gt;</div>
    <div>Role</div><div>{badge}</div>
    <div>Issuer</div><div>{claims.get('iss','—')}</div>
  </div>
  <label>Your session token (JWT)</label>
  <div class="tok">{token}</div>
</div>
<div class="card">
  <h2>Restricted area</h2>
  <p class="sub">The Admin Console is available to administrators only.</p>
  <form method="post" action="/set-token">
    <label>Session token &mdash; paste a token to use for the request</label>
    <textarea name="token">{token}</textarea>
    <div class="row">
      <button class="btn" type="submit" formaction="/set-token">Open Admin Console &rarr;</button>
      <a class="btn ghost" href="/logout">Sign out</a>
    </div>
  </form>
  <p class="note">Tip: this box lets you swap the token used for the next request.</p>
</div>"""
    return page("Dashboard", body)


@app.post("/set-token")
def set_token():
    token = (request.form.get("token") or "").strip()
    resp = make_response(redirect("/admin"))
    resp.set_cookie("session", token, samesite="Lax")
    return resp


@app.get("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("session")
    return resp


@app.get("/admin")
def admin():
    token = _current_token()
    wants_json = "application/json" in request.headers.get("Accept", "") \
        or request.headers.get("Authorization", "").startswith("Bearer ")
    if not token:
        if wants_json:
            return jsonify(error="missing token"), 401
        return redirect("/")
    try:
        claims = insecure_verify(token)
    except Exception as e:
        if wants_json:
            return jsonify(error=f"invalid token: {e}"), 401
        return page("Access denied", f"""
<div class="card denied"><div class="big-ic ic">&#10005;</div>
<h1>Invalid token</h1><p class="sub">{e}</p>
<a class="btn ghost" href="/dashboard">&larr; Back</a></div>"""), 401

    if claims.get("role") != "admin":
        if wants_json:
            return jsonify(error="forbidden: admin role required",
                           your_role=claims.get("role")), 403
        return page("Access denied", f"""
<div class="card denied"><div class="big-ic ic">&#128274;</div>
<h1>403 &middot; Access denied</h1>
<p class="sub">The Admin Console requires the <b>admin</b> role.
Your token carries role <b>{claims.get('role')}</b>.</p>
<a class="btn ghost" href="/dashboard">&larr; Back to dashboard</a></div>"""), 403

    if wants_json:
        return jsonify(message="Welcome, admin!", flag=FLAG, claims=claims)
    return page("Admin Console", f"""
<div class="card granted"><div class="big-ic" style="color:var(--ok)">&#9989;</div>
<h1>Welcome to the Admin Console</h1>
<p class="sub">Authenticated as <b>{claims.get('name', claims.get('sub','admin'))}</b>
with role <span class="badge admin">&#10003; admin</span></p>
<ul class="list">
  <li><span>Tenant users</span><span class="muted">14,982</span></li>
  <li><span>Active API keys</span><span class="muted">37</span></li>
  <li><span>Billing plan</span><span class="muted">Enterprise</span></li>
  <li><span>Master API secret</span><span class="muted">sk_live_9f3c…a71e</span></li>
</ul>
<div class="flag">FLAG: {FLAG}</div>
<a class="btn ghost" href="/logout" style="margin-top:18px">Sign out</a></div>""")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)

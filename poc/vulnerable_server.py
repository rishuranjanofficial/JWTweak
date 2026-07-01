#!/usr/bin/env python3
"""
vulnerable_server.py  -  a DELIBERATELY INSECURE JWT demo target for JWTweak.

This is a teaching/PoC target only. It reproduces two classic, real-world JWT
verification bugs on purpose. NEVER copy this verification logic into anything
real.

Run:
    pip install flask pyjwt cryptography
    python3 vulnerable_server.py
    # server listens on http://127.0.0.1:5000

Endpoints:
    GET  /                 - info
    POST /login            - issues a normal RS256 "user" token
    GET  /public_key.pem   - the server's public verification key (as many apps expose)
    GET  /admin            - protected; needs a token whose role == "admin"
                             Send it as:  Authorization: Bearer <token>

The vulnerabilities (both forgeable with JWTweak):
    1. alg:none is accepted           -> unsigned admin token is trusted.
    2. Algorithm confusion            -> the ONE public key is (mis)used as an
       (RS256 expected, HS256 given)     HMAC secret, so an HS256 token signed
                                          with the public key verifies.

SECURITY NOTE ON KEYS
    This script GENERATES its own throwaway RSA key pair on first run
    (private_key.pem / public_key.pem in this folder) and reuses it after.
    Those keys protect nothing real and exist only for this local lab, but as a
    matter of good hygiene they are still secret material: they are NOT meant to
    be committed to a repository. Add them to .gitignore (a sample is shipped
    with this lab). Never commit real private keys anywhere, ever - not even for
    a demo, because it normalises a dangerous habit and trips secret scanners.
"""
import base64
import hashlib
import hmac
import json
import os

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
import jwt  # only used to MINT the legitimate token, not to verify it

app = Flask(__name__)


def _load_or_create_keys():
    """Generate a throwaway key pair on first run; reuse it afterwards.

    Keys are written next to this script so the lab is self-contained, but they
    are gitignored - the repo should never carry a private key.
    """
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


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------- #
#  INSECURE verifier - this is the whole point of the demo. Do not reuse.
# --------------------------------------------------------------------------- #
def insecure_verify(token):
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    alg = header.get("alg", "")
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # BUG #1: trust alg:none and skip verification entirely
    if alg.lower() == "none":
        return payload

    # BUG #2: the same public key is used for HMAC when the header says HS*
    if alg in _HASHES:
        expected = base64.urlsafe_b64encode(
            hmac.new(PUBLIC_KEY_PEM, signing_input, _HASHES[alg]).digest()
        ).rstrip(b"=").decode()
        if hmac.compare_digest(expected, sig_b64):
            return payload
        raise ValueError("bad HMAC signature")

    # "Normal" RS256 path
    if alg in ("RS256", "RS384", "RS512"):
        h = {"RS256": hashlib.sha256, "RS384": hashlib.sha384,
             "RS512": hashlib.sha512}[alg]
        from cryptography.hazmat.primitives import hashes
        hash_alg = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(),
                    "RS512": hashes.SHA512()}[alg]
        PUBLIC_KEY.verify(b64url_decode(sig_b64), signing_input,
                          padding.PKCS1v15(), hash_alg)
        return payload

    raise ValueError(f"unsupported alg {alg}")


@app.get("/")
def index():
    return ("<h3>Vulnerable JWT demo</h3>"
            "<p>POST /login to get a user token, then GET /admin with "
            "<code>Authorization: Bearer &lt;token&gt;</code>.</p>"
            "<p>Public key: <a href='/public_key.pem'>/public_key.pem</a></p>")


@app.post("/login")
def login():
    token = jwt.encode({"sub": "alice", "role": "user", "iss": "vuln-demo"},
                       PRIVATE_KEY, algorithm="RS256",
                       headers={"kid": "demo-key-1"})
    return jsonify(access_token=token, token_type="Bearer", role="user")


@app.get("/public_key.pem")
def public_key():
    return app.response_class(PUBLIC_KEY_PEM, mimetype="application/x-pem-file")


@app.get("/admin")
def admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify(error="missing bearer token"), 401
    token = auth[7:].strip()
    try:
        claims = insecure_verify(token)
    except Exception as e:
        return jsonify(error=f"invalid token: {e}"), 401
    if claims.get("role") != "admin":
        return jsonify(error="forbidden: admin role required",
                       your_role=claims.get("role")), 403
    return jsonify(message="Welcome, admin!",
                   flag="JWTweak{alg_confusion_and_none_win}",
                   claims=claims)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)

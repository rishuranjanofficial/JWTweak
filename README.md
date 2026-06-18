# JWTweak

[![GitHub stars](https://img.shields.io/github/stars/rishuranjanofficial/JWTweak?logoColor=blue&style=social)](https://github.com/rishuranjanofficial/JWTweak/stargazers)   [![GitHub forks](https://img.shields.io/github/forks/rishuranjanofficial/JWTweak?logoColor=blue&style=social)](https://github.com/rishuranjanofficial/JWTweak/network)

## Introduction
With the global increase in JSON Web Token (JWT) usage, the JWT attack surface has grown well beyond the classic `alg` switch. **JWTweak v2.0** is a JWT security‑testing toolkit that detects the algorithm of an input token, analyses it for risky configuration, and generates forged or tampered tokens across a wide range of modern attack classes — so you can quickly check how a target validates (or fails to validate) its JWTs.

It runs as an **interactive menu** for exploration and as a **scriptable CLI** for automation and pipelines.

> ⚠️ **For authorised security testing and research only.** Only test systems you own or have explicit permission to assess.

## What's new in v2.0
- **Algorithm confusion (RS/EC → HS)** done correctly with manual HMAC signing, so it works against modern libraries that block public keys as HMAC secrets.
- **Key‑resolution header injection**: `jwk` (CVE‑2018‑0114), `jku` (attacker‑hosted JWKS), `x5u` / `x5c` (attacker certificate).
- **`kid` injection**: path traversal (`/dev/null` → empty key), SQL injection, command‑injection probes.
- **Claim tampering**: drop/extend `exp`, escalate `role`/`admin`, edit or replace any claim.
- **HMAC secret brute‑force** with a wordlist (offline secret cracking).
- **Modern algorithms** for re‑signing: `HS256/384/512`, `RS*`, `PS*`, `ES256/384/512`, `EdDSA`.
- **`alg:none` casing variants** (`none`, `None`, `NONE`, `nOnE`) and signature stripping/bit‑flip.
- **Risk analysis** of the input token (flags `none`, weak HMAC, `jku`/`jwk`/`x5u`/`kid`, missing/expired `exp`, …).
- **Full attack suite** that emits every candidate token to a file for use in Burp/Repeater or a fuzzer.
- Reworked **UX**: grouped looping menu, colour output (auto‑disabled when piped or via `--no-color`), token from string/file/stdin, and a full `argparse` CLI.
- Fixed compatibility with **PyJWT 2.x** (the previous `.decode('utf')` call no longer exists) and migrated key/cert handling to the maintained **`cryptography`** library.

## Requirements
- Python 3.8+
- `pip install -r requirements.txt`  (PyJWT and cryptography)

## Usage

### Interactive
```bash
python3 JWTweak.py
# or pass a token / file up front
python3 JWTweak.py -t eyJhbG...        # token string
python3 JWTweak.py -t token.jwt        # file containing a token
```

### Non‑interactive (scriptable)
```bash
# Decode and risk-analyse
python3 JWTweak.py -t token.jwt --decode

# alg:none variants
python3 JWTweak.py -t token.jwt --attack none

# Algorithm confusion using the target's public key
python3 JWTweak.py -t token.jwt --attack confusion --public-key pub.pem

# Embed an attacker key in the jwk header (CVE-2018-0114)
python3 JWTweak.py -t token.jwt --attack jwk

# jku / x5u injection (point at a host you control)
python3 JWTweak.py -t token.jwt --attack jku --jku https://you.example/jwks.json
python3 JWTweak.py -t token.jwt --attack x5 --x5u https://you.example/cert.pem

# kid path traversal / SQLi / command-injection probes
python3 JWTweak.py -t token.jwt --attack kid --injected-key mykey

# Tamper claims, then re-sign as needed
python3 JWTweak.py -t token.jwt --attack tamper --set-claim role=admin --set-claim isAdmin=true
python3 JWTweak.py -t token.jwt --attack resign --alg ES256

# Crack a weak HMAC secret
python3 JWTweak.py -t token.jwt --attack crack --wordlist rockyou.txt

# Run the whole battery and save every candidate token
python3 JWTweak.py -t token.jwt --attack suite --public-key pub.pem -o tokens.txt
```

## Attack coverage
| Area | Options |
| --- | --- |
| Recon | decode + risk analysis |
| Signature / algorithm | `alg:none` variants, algorithm confusion, re‑sign (HS/RS/PS/ES/EdDSA), signature strip / bit‑flip |
| Key‑resolution headers | `jwk`, `jku`, `x5u`, `x5c` injection |
| Key ID | `kid` path traversal, SQLi, command‑injection |
| Claims | drop/extend `exp`, role/admin escalation, arbitrary claim edits |
| Cracking | HMAC secret brute‑force (wordlist) |
| Automation | full attack suite → file |

## Author
**Rishu Ranjan**
> [![](https://img.shields.io/twitter/follow/secureit_rrj?style=social)](https://twitter.com/intent/follow?screen_name=secureit_rrj)   [![](https://static-exp1.licdn.com/sc/h/95o6rrc5ws6mlw6wqzy0xgj7y)](https://www.linkedin.com/in/rishuranjan/)

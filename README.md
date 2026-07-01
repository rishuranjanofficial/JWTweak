# JWTweak

[![GitHub stars](https://img.shields.io/github/stars/rishuranjanofficial/JWTweak?logoColor=blue&style=social)](https://github.com/rishuranjanofficial/JWTweak/stargazers)   [![GitHub forks](https://img.shields.io/github/forks/rishuranjanofficial/JWTweak?logoColor=blue&style=social)](https://github.com/rishuranjanofficial/JWTweak/network)

## Introduction
**JWTweak** is a guided, fully-offline JWT security-testing toolkit. It detects the algorithm of an input token, analyses it for risky configuration, recommends the attacks that fit, and walks you through each one - no flags to memorise.

Just run it:

```bash
python3 JWTweak.py
```

Paste a token, and JWTweak decodes it, shows a risk report, and presents a smart menu with the relevant attacks highlighted. Every attack runs **100% offline** - nothing is ever sent over the network.

> ⚠️ **For authorised security testing and research only.**

## Highlights
- **Zero flags.** Run it, paste a token, follow the menu. Nothing to look up.
- **Fully offline.** No attack makes a network call. `jku`/`x5u` artifacts are generated locally, and JWTweak can even spin up a **built-in local web server** so you can host them without any external service.
- **Smart & guided.** Auto-decodes, runs a risk analysis, and marks the attacks that make sense for *your* token as *recommended*.
- **Polished TUI** via [`rich`](https://github.com/Textualize/rich) - panels, syntax-highlighted JSON, a risk table, and a live cracking progress bar. Falls back to a clean plain-text UI automatically if `rich` isn't installed.

## Attack coverage
| Area | What it does |
| --- | --- |
| Recon | decode + risk analysis |
| Signature / algorithm | `alg:none` variants, algorithm confusion (RS/ES → HMAC), re-sign with `HS/RS/PS/ES/EdDSA`, signature strip / bit-flip |
| Key-resolution headers | `jwk` (CVE-2018-0114), `jku`, `x5u`, `x5c` injection - with optional built-in local hosting |
| Claims / keys | `kid` path traversal / SQLi / command injection, interactive claim tampering, offline HMAC secret cracking |
| Automation | one-tap "recommended suite" that writes every applicable token to a file |

## Requirements
- Python 3.8+
- `pip install -r requirements.txt`

`PyJWT` and `cryptography` are required; `rich` is optional (recommended) and only affects presentation.

## Usage
Normally you never pass anything:

```bash
python3 JWTweak.py
```

For convenience you can pre-load a token or file, or force the plain UI:

```bash
python3 JWTweak.py eyJhbG...              # start with a token
python3 JWTweak.py token.jwt              # start with a file
python3 JWTweak.py --no-rich --no-color   # plain-text UI
```

## Author
**Rishu Ranjan**
> [![](https://img.shields.io/twitter/follow/secureit_rrj?style=social)](https://twitter.com/intent/follow?screen_name=secureit_rrj)   [![](https://static-exp1.licdn.com/sc/h/95o6rrc5ws6mlw6wqzy0xgj7y)](https://www.linkedin.com/in/rishuranjan/)

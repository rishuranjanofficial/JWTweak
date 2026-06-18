# Changelogs
## Version-1.0 (28-Apr-2020)
### Feature
- Option to Detect the algorithm of the input JWT
- Base64 decode the input JWT Token
- Generate new JWT Token by changing algorthim to `None` and `HS256/384/512`

## Version-1.1 (29-Apr-2020)
### Feature
- Exception Handling implemented

## Version-1.1.1 (30-Apr-2020)
### Feature
- Bug fixes

## Version-1.5 (24-May-2020)
### Feature
- Generate new JWT Token by changing algorthim to `RS256/384/512`
- Generate Public and Private key pair, if not provided as input for signing

## Version-1.5.1 (30-May-2020)
### Feature
- Bug fixes

## Version-1.6 (03-July-2020)
### Feature
- Bug fixes

## Version-1.7 (17-June-2025)
### Feature
- Bug fixes
## Version-2.0 (18-June-2026)
### Added
- Algorithm confusion attack (RS/EC public key used as HMAC secret) via manual HMAC signing, effective against libraries that block public keys as HMAC secrets (CVE-2022-29217 hardening).
- Key-resolution header injection: `jwk` (CVE-2018-0114), `jku` (attacker-hosted JWKS), `x5u` and `x5c` (attacker certificate).
- `kid` injection payloads: path traversal to `/dev/null` (empty HMAC key), SQL injection, and command-injection probes.
- Claim tampering: remove/extend `exp`, escalate `role`/`admin`, edit or replace arbitrary claims.
- Offline HMAC secret brute-force using a wordlist.
- Re-signing support for modern algorithms: `PS256/384/512`, `ES256/384/512`, and `EdDSA` (in addition to `HS*` and `RS*`).
- `alg:none` casing variants (`none`, `None`, `NONE`, `nOnE`) plus signature stripping and bit-flip.
- Input-token risk analysis (flags `none`/empty alg, weak HMAC, `jku`/`jwk`/`x5u`/`kid`, missing/expired `exp`).
- Full attack-suite mode that writes every candidate token to a file.
- Non-interactive `argparse` CLI for automation, alongside a reworked grouped/looping interactive menu.
- Colour output that auto-disables when piped or via `--no-color`; token input from string, file, or stdin.

### Changed
- Rewrote the tool from a single ~800-line function into modular, de-duplicated functions.
- Migrated proper base64url handling (no more standard-base64 edge cases).
- Migrated key/certificate handling from `pycryptodomex` to the maintained `cryptography` library.

### Fixed
- Compatibility with PyJWT 2.x, where `jwt.encode()` returns `str` (the old `.decode('utf')` calls crashed on modern installs).
- Bug where changing the algorithm to `RS512` incorrectly set the header to `RS384`.
- Replaced bare `except:` blocks with targeted error handling and clearer messages.

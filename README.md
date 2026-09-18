# JWT Audit Lab

A black-box JWT authentication attack-surface auditor, proven against a deliberately
vulnerable auth server and a correctly hardened one. **Authorized security-lab use
only** — everything runs locally in Docker; no code targets any real or external
system. Built for the SYNORA hackathon (SRM AP).

## Quickstart

```bash
docker compose up
```

Then run the auditor against a target (from `auditor/`, after `pip install -e .`):

```bash
jwtaudit audit --base-url http://localhost:4000    # vulnerable server
jwtaudit audit --base-url http://localhost:4001    # secure server
```

## Design

The auditor is **active, not passive**: it does not grade a server by inspecting
headers or decoding claims, it *forges* a token for each attack class and sends it
to a protected endpoint. A finding is reported `CONFIRMED` only when a forged request
returns **HTTP 200 and** the response reveals identity or data the legitimate
normal-user baseline provably could not reach. Static header or claim observations may
raise a `SUSPECTED` hint but never a standalone `CONFIRMED`.

This is the zero-false-positive discipline: the auditor proves exploitability
empirically, which is why it lands four confirmed findings on the vulnerable server
while correctly staying silent on `signature_bypass`, a non-vulnerability there.

## Probes

| Probe | CWE | Attack | Expected on vulnerable | Expected on secure |
|-------|-----|--------|------------------------|--------------------|
| `none_alg` | CWE-347 | Unsigned `alg:none` token asserting admin | CONFIRMED | NOT_VULNERABLE |
| `weak_secret` | CWE-326 | Brute-force the HMAC secret, re-sign as admin | CONFIRMED | NOT_VULNERABLE |
| `alg_confusion` | CWE-347 | RS256→HS256: sign HS256 with the RSA public key | CONFIRMED | NOT_VULNERABLE |
| `signature_bypass` | CWE-347 | Tamper claims, keep the original signature | NOT_VULNERABLE | NOT_VULNERABLE |
| `expiration` | CWE-613 | Forge an otherwise-valid token with a past `exp` | CONFIRMED | SKIPPED |

`expiration` is capability-dependent: it reuses the forge primitive established by the
Phase A probes (alg:none or a cracked secret). On the secure server no primitive is
established, so it is correctly `SKIPPED`.

## Live Demo

```powershell
.\run_demo.ps1
```

Boots both servers, audits each, and writes `vulnerable-report.json` and
`secure-report.json`. Expected result: **4 CONFIRMED on the vulnerable server, 0 on the
secure server.**

## Tests

```bash
pytest tests/ -v
```

Unit tests for the cracker and the escalation gate run without a network. The
regression tests boot both Node servers as subprocesses and assert the exact
CONFIRMED / NOT_VULNERABLE sets on each. Requires Node.js and Python 3.11+.

## Starter Kit

Want to test your own server?
Download starter-kit/ from this repo.

```
npm install && npm start
```

Then point JWT Audit Lab at http://localhost:4000

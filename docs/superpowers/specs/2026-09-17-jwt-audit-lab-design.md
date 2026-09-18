# JWT Audit Lab — Design Spec

- **Date:** 2026-09-17
- **Project:** `jwt-audit-lab` — a black-box JWT auth attack-surface auditor, proven against a deliberately vulnerable auth server and a correctly hardened one.
- **Context:** Authorized security lab for the SYNORA hackathon (SRM AP). Everything runs locally in Docker. No code targets any real or external system.
- **Status:** Approved design, pre-implementation. No server or auditor code written yet.

---

## 1. Goal & success criteria

Build a tool that empirically proves which JWT authentication weaknesses are *exploitable* on a target, with **zero false positives**. Success is defined concretely:

1. Run against the **vulnerable server** → exactly these findings are `CONFIRMED`: `none_alg`, `weak_secret`, `alg_confusion`, `expiration`. `signature_bypass` is tested and correctly reported `NOT_VULNERABLE`.
2. Run against the **secure server** → **zero** `CONFIRMED` findings (and no spurious `SUSPECTED` noise).
3. Every finding is a structured object (severity, CWE, evidence, remediation) — no print-only logic.
4. The auditor is **black-box**: it knows only base URL, login path, protected path, admin path, and one normal-user credential. It never imports or reads server code.

The strongest single moment of the demo is the auditor finding 4 real bugs **and** staying silent on `signature_bypass` — proving it confirms exploitability rather than pattern-matching headers.

---

## 2. Non-negotiable design rules (carried from the brief)

1. **Black-box.** Auditor inputs: base URL, login path, protected path, admin path, valid credentials. Nothing else.
2. **CONFIRMED gate.** A finding is `CONFIRMED` only when a forged request returns **HTTP 200 AND** the response shows escalated identity or protected data the baseline user could not reach. Static header/claim inspection may yield `SUSPECTED`, never a standalone `CONFIRMED`. This zero-false-positive rule is respected in every probe.
3. **Structured findings.** Every probe returns a `Finding` (severity, cwe, evidence = forged token + response snippet + status, remediation).
4. **Runs on both servers.** CONFIRMED findings on the vulnerable one; zero findings on the secure one.

**Conventions:** type hints on all Python; small single-purpose modules; no secrets in source.

---

## 3. Repository layout

```
jwt-audit-lab/
  targets/
    vulnerable-server/        Node 20 + Express + jsonwebtoken (deliberately broken)
      src/server.js
      src/keys/                RSA keypair (dev-only, generated at build)
      package.json
      Dockerfile
    secure-server/            Node 20 + Express + jsonwebtoken (correct impl)
      src/server.js
      src/keys/
      package.json
      Dockerfile
  auditor/
    jwtaudit/
      __init__.py
      cli.py                  typer entrypoint
      client.py               httpx AuthClient + baseline + escalation predicate
      models.py               Finding, Target, Severity, Verdict, ForgeCapability
      cracker.py              pure offline HS256 secret brute-force
      report.py               rich console table + JSON writer
      forge.py                token-forging helpers (none, HS256-sign, tamper)
      probes/
        __init__.py
        base.py               Probe ABC + registry
        none_alg.py
        weak_secret.py
        alg_confusion.py
        signature_bypass.py
        expiration.py
    wordlists/
      common-secrets.txt
    pyproject.toml
    Dockerfile
  tests/
    test_cracker.py           unit, no network
    test_escalation.py        unit, no network
    test_regression.py        boots both servers, asserts verdict sets
    conftest.py               fixtures: boot servers (docker compose or subprocess)
  docker-compose.yml
  README.md
```

---

## 4. Target servers

Both servers expose an identical HTTP contract so the auditor cannot tell them apart except by behavior.

### 4.1 Shared contract

| Method | Path | Behavior |
|--------|------|----------|
| `POST` | `/login` | Body `{username, password}`. On valid creds returns `{ "token": "<jwt>" }`. |
| `GET` | `/me` | Requires token. Returns `{ "username", "role" }` from the (verified) identity. |
| `GET` | `/admin` | Requires token **and** admin role. Returns `{ "secret_data": "...", "role": "admin" }`. Non-admin → 403. |
| `GET` | `/.well-known/jwks.json` | Returns the RSA public key in JWKS form. |

**Seed identities (both servers):**
- `alice` / `password123` → role `user`  *(this is the only credential the auditor is given)*
- `admin` / (unknown to auditor) → role `admin`  *(exists so `/admin` returns real data; auditor must never log in as this)*

**Baseline truth the auditor establishes at runtime:** logging in as `alice` and calling `/admin` returns **403** on both servers. Any forged token that turns that into a **200 with `secret_data`** is a confirmed escalation.

### 4.2 Vulnerable server (discriminating broken impl)

Signs login tokens as **HS256 using a weak secret** (`"secret"`, planted in the wordlist), 15-minute expiry. Also holds an RSA keypair and publishes its public key at the JWKS endpoint.

Its auth middleware is deliberately misconfigured with a per-algorithm branch, each branch a real-world footgun:

- `alg = none` → **trusted without a signature** → enables **P1 (none_alg)**.
- `alg = HS256` → accepted if the signature verifies against **the weak secret OR the RSA public key bytes** → enables **P2 (weak_secret)** and **P3 (alg_confusion)**.
- `alg = RS256` → verified against the public key.
- A **garbage/invalid signature** on a real algorithm → **rejected (401)** → `signature_bypass` (P4) is *not present here*.
- **Expiration is not enforced on any accepting branch** (`ignoreExpiration: true` everywhere it verifies) → enables **P5 (expiration)**. This is what lets an *accepted* forged token (via the `alg:none` or cracked-secret primitive) carry a past `exp` and still reach `/admin`.

`/admin` reads `role` from the (mis)verified claims, so any forged `role=admin` token that the middleware accepts reaches admin data. Result: 4 CONFIRMED (`none_alg`, `weak_secret`, `alg_confusion`, `expiration`) and a correct silence on `signature_bypass`.

### 4.3 Secure server (correct impl)

- Signs tokens as **RS256** with a 2048-bit key; publishes the public key via JWKS.
- Verifies with `jwt.verify(token, publicKey, { algorithms: ['RS256'] })` — algorithm **pinned**, so `none` and HS256 confusion are rejected.
- Expiration enforced (default `jwt.verify` behavior; no `ignoreExpiration`).
- No HMAC secret exists anywhere → nothing to crack.
- `/admin` gated on the verified `role` claim.

Every forged token → 401/403. Auditor → zero findings.

> **Realism note:** the vulnerable server's multi-branch middleware is intentionally contrived so a single target exercises four distinct root causes (CWE-347, CWE-321, CWE-347 confusion, CWE-613). Each branch individually mirrors a bug seen in the wild; combining them keeps the lab to one vulnerable service while still letting the auditor *discriminate* between vulns rather than finding one bug several ways.

---

## 5. Auditor architecture

### 5.1 Data model (`models.py`)

```python
class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"        # forged 200 + proven escalation
    SUSPECTED = "SUSPECTED"        # static hint only, never standalone-confirmed
    NOT_VULNERABLE = "NOT_VULNERABLE"
    ERROR = "ERROR"

class Severity(str, Enum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"; MEDIUM = "MEDIUM"; LOW = "LOW"; INFO = "INFO"

@dataclass(frozen=True)
class Target:
    base_url: str; login_path: str; protected_path: str; admin_path: str
    username: str; password: str

@dataclass
class Evidence:
    forged_token: str | None
    request_line: str            # e.g. "GET /admin"
    status_code: int | None
    response_snippet: str        # truncated body
    note: str = ""               # e.g. "cracked secret: 'secret'"

@dataclass
class Finding:
    probe_id: str; title: str
    verdict: Verdict; severity: Severity; cwe: str
    evidence: Evidence; remediation: str

@dataclass
class ForgeCapability:
    """Whether the auditor can mint a token the target will accept, and how."""
    gained: bool
    method: str | None           # "alg:none" | "cracked-secret" | "rs256->hs256-confusion"
    detail: str = ""             # e.g. "secret='secret'"
    # mint(claims) -> str : produce an accepted token asserting the given claims
    mint: Callable[[dict], str] | None = None
```

### 5.2 Baseline & escalation predicate (`client.py`)

`AuthClient` wraps `httpx.Client`:
- `login() -> str` — POST creds, return token.
- `get(path, token) -> httpx.Response`.
- `capture_baseline() -> Baseline` — legit-user token; records `/me` body (`role=user`), `/admin` status (expect 403), and admin-only markers.
- `is_escalated(resp, baseline) -> bool` — **the CONFIRMED gate**. Returns True iff `resp.status_code == 200` **and** the body shows something the baseline user could not reach: admin markers on `/admin`, or `role=admin` on `/me` where baseline showed `role=user`. Pure comparison against captured baseline, no server-code knowledge.

### 5.3 Forge helpers (`forge.py`) and cracker (`cracker.py`)

- `forge.py` — build tokens: `none_token(claims)`, `hs256_token(claims, secret)`, `tamper_claims(token, patch)`, `pubkey_as_hmac_token(claims, pubkey_pem)`. Pure, tested without network.
- `cracker.py` — `crack_hs256(token, wordlist_path) -> str | None`: for each candidate, locally recompute the HS256 signature and compare; return the first match. Pure/offline; unit-tested.

### 5.4 Probes (`probes/`)

Each probe implements:

```python
class Probe(ABC):
    id: str; title: str; severity: Severity; cwe: str; remediation: str
    @abstractmethod
    def run(self, client, target, baseline, capability) -> Finding: ...
```

| Probe | Vector | CWE | Verdict logic |
|-------|--------|-----|---------------|
| `none_alg` | `alg:none`, `role=admin`, empty signature → `/admin` | CWE-347 | CONFIRMED iff `is_escalated`. Also *provides* forge capability. |
| `weak_secret` | crack HS256 secret from wordlist, re-sign `role=admin` → `/admin` | CWE-321 | CONFIRMED iff crack succeeds **and** `is_escalated`. Provides forge capability. |
| `alg_confusion` | fetch JWKS pubkey, HS256-sign `role=admin` with pubkey bytes → `/admin` | CWE-347 | Runs only if JWKS pubkey discoverable; CONFIRMED iff `is_escalated`. Provides forge capability. |
| `signature_bypass` | tamper `role=admin`, keep alg, replace signature with garbage → `/admin` | CWE-345 | CONFIRMED iff `is_escalated` (server ignored the bad signature). |
| `expiration` | using best available `ForgeCapability`, mint a token with `exp` in the past → `/admin` | CWE-613 | **Capability-dependent**: if no forge capability was gained, cannot mint an accepted token → `NOT_VULNERABLE`. Otherwise CONFIRMED iff `is_escalated` despite expiry. |

**Static hints → `SUSPECTED` only:** any header/claim observation (e.g. JWKS present, `alg` echoed) may add a `SUSPECTED` note but never a standalone `CONFIRMED`.

### 5.5 Run flow & the signing-capability summary (`cli.py`)

```
1. Build Target from CLI flags (URLs, paths, creds).
2. client.login() as normal user; capture_baseline().
3. PHASE A — forgery-primitive probes, in order:
     none_alg, weak_secret, alg_confusion, signature_bypass
   As each runs, if it yields an accepted-token primitive, record it into
   a ForgeCapability (priority: alg:none > cracked-secret > confusion).
4. PRINT SIGNING-CAPABILITY SUMMARY (one line), e.g.:
     "Forge capability: GAINED via alg:none  → claim probes armed"
     or
     "Forge capability: NOT GAINED           → claim probes cannot confirm"
   This makes the attack chain visible in demo output before capability-
   dependent probes run.
5. PHASE B — capability-dependent probes:
     expiration  (uses ForgeCapability.mint to forge an expired token)
6. report.render(findings)  → rich table to console
   report.write_json(findings, path) → machine-readable report
7. Exit non-zero if any Verdict.CONFIRMED (CI-friendly).
```

On the **secure server**, Phase A yields no primitive → summary prints `NOT GAINED` → `expiration` returns `NOT_VULNERABLE` → zero CONFIRMED overall.

### 5.6 Reporting (`report.py`)

- **Console:** `rich` table — probe id, verdict (color-coded), severity, CWE, one-line evidence. Followed by per-CONFIRMED detail blocks (forged token, request line, status, response snippet, remediation). The signing-capability line is printed between phases (§5.5).
- **JSON:** `{ target, generated_at, forge_capability, findings: [Finding...], summary: {confirmed, suspected, not_vulnerable} }` — used by demo/writeup and asserted by regression tests.

---

## 6. CLI surface

```
jwtaudit audit \
  --base-url http://localhost:4000 \
  --login-path /login --protected-path /me --admin-path /admin \
  --username alice --password password123 \
  --wordlist auditor/wordlists/common-secrets.txt \
  --json-out report.json
```

Sensible defaults for paths so the demo command is short. `--base-url http://localhost:4001` targets the secure server unchanged.

---

## 7. Testing strategy

- **Unit (no network):**
  - `test_cracker.py` — `crack_hs256` finds a planted secret, returns `None` on miss.
  - `test_escalation.py` — `is_escalated` true only on 200-with-admin-markers vs. a captured baseline; false on 403, on 200-without-escalation, and on non-200.
- **Regression (boots both servers via `conftest.py` fixtures — docker compose or node subprocess):**
  - vulnerable → `CONFIRMED` set == `{none_alg, weak_secret, alg_confusion, expiration}`, and `signature_bypass` == `NOT_VULNERABLE`.
  - secure → zero `CONFIRMED`; `expiration` == `NOT_VULNERABLE`; forge capability == `NOT GAINED`.

These two regression assertions are the executable form of the success criteria in §1.

---

## 8. Docker

- `docker-compose.yml` services: `vulnerable-server` (4000), `secure-server` (4001), and `auditor` (build image, run on demand against a chosen base URL).
- One `Dockerfile` per component. RSA dev keypairs generated at image build (never committed as real secrets; lab-only).
- README documents: `docker compose up -d`, then the two `jwtaudit audit` demo commands and the expected 4-vs-0 outcome.

---

## 9. Out of scope (YAGNI)

- `kid`/`jku`/`jwk` header-injection probes, `nbf`/`iat`, and `aud`/`iss` confusion — deferred; the probe registry makes them easy to add later.
- Any real/external target. Refresh-token flows, cookie auth, mTLS.
- Auto-remediation or patching of targets.

---

## 10. Root-cause / CWE map (for the report & README)

| Finding | Root cause | CWE |
|---------|-----------|-----|
| `none_alg` | accepts unsigned `alg:none` tokens | CWE-347 (Improper Verification of Cryptographic Signature) |
| `weak_secret` | HMAC signing secret is guessable | CWE-321 (Use of Hard-coded / Weak Cryptographic Key) |
| `alg_confusion` | verifier not pinned to one algorithm; RS256→HS256 | CWE-347 |
| `signature_bypass` | signature not verified at all | CWE-345 (Insufficient Verification of Data Authenticity) |
| `expiration` | `exp` not enforced | CWE-613 (Insufficient Session Expiration) |
```

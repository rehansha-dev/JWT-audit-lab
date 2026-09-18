# JWT Audit Lab — Implementation Plan (phased by component)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan. This plan is phased by component per the operator's request; each phase is expanded into bite-sized TDD steps (with test code) at execution time — no implementation code is written during planning.

**Goal:** Build a black-box JWT attack-surface auditor that lands 4 CONFIRMED findings on a deliberately vulnerable server and zero on a hardened one.

**Architecture:** Two Node/Express target servers (vulnerable, secure) plus a Python `typer`/`httpx` auditor with per-probe modules. The auditor forges tokens, sends them to `/admin`, and confirms only on HTTP 200 + proven privilege escalation against a captured baseline.

**Tech Stack:** Node 20 + Express + jsonwebtoken (targets); Python 3.11 + PyJWT + cryptography + httpx + rich + typer (auditor); pytest; Docker Compose.

**Spec:** `docs/superpowers/specs/2026-09-17-jwt-audit-lab-design.md`

## Global Constraints

- Auditor is black-box: inputs limited to base URL, login/protected/admin paths, one normal-user credential. Never imports or reads server code.
- `CONFIRMED` only on HTTP 200 **AND** proven escalation vs. baseline. Static hints → `SUSPECTED` at most.
- Every probe returns a structured `Finding` (severity, cwe, evidence, remediation). No print-only logic.
- Type hints on all Python; small single-purpose modules; no secrets in source (dev RSA keys generated at build).
- Expected outcome: vulnerable → CONFIRMED `{none_alg, weak_secret, alg_confusion, expiration}`, `signature_bypass` = NOT_VULNERABLE; secure → zero CONFIRMED.

---

## Phase 1: `targets/vulnerable-server` (Node/Express)

**Files created/modified:**
- Create `targets/vulnerable-server/package.json` (express, jsonwebtoken)
- Create `targets/vulnerable-server/src/server.js` (routes + discriminating broken middleware from spec §4.2)
- Create `targets/vulnerable-server/src/keys/generate.js` (emit dev RSA keypair at build/start; keys git-ignored)
- Create `targets/vulnerable-server/Dockerfile`, `.dockerignore`, `.gitignore`

**How to manually verify before moving on:**
- `npm install && node src/server.js` → listens on 4000.
- `POST /login {alice/password123}` → returns an HS256 token.
- `GET /me` with that token → `{username: alice, role: user}`.
- `GET /admin` with alice's token → **403**.
- `GET /.well-known/jwks.json` → RSA public key.
- Hand-craft an `alg:none`, `role=admin` token and hit `/admin` → **200 + secret_data** (proves the target is genuinely vulnerable).

**Does NOT include:** secure server, auditor, docker-compose, JWKS-as-HMAC verification testing beyond a smoke check. Server runs standalone via `node`.

---

## Phase 2: `targets/secure-server` (Node/Express)

**Files created/modified:**
- Create `targets/secure-server/package.json`
- Create `targets/secure-server/src/server.js` (RS256-only, `algorithms:['RS256']`, exp enforced, role-gated `/admin`)
- Create `targets/secure-server/src/keys/generate.js`, `Dockerfile`, `.dockerignore`, `.gitignore`

**How to manually verify before moving on:**
- Run on **4001**. `POST /login` → RS256 token; `GET /me` → role user; `GET /admin` with alice → **403**.
- `alg:none` token → **401**. Expired RS256 token → **401**. HS256 token signed with the JWKS public key → **401**.
- JWKS endpoint returns the RSA public key.

**Does NOT include:** auditor, docker-compose. Confirms the hardened baseline by hand so later "zero findings" is trustworthy.

---

## Phase 3: Auditor core (`models`, `client`, `cracker`, probe `base`, `cli` scaffold)

**Files created/modified:**
- Create `auditor/pyproject.toml` (deps + `jwtaudit` console script), `auditor/jwtaudit/__init__.py`
- Create `auditor/jwtaudit/models.py` (`Verdict`, `Severity`, `Target`, `Evidence`, `Finding`, `ForgeCapability`)
- Create `auditor/jwtaudit/client.py` (`AuthClient.login/get`, `capture_baseline`, `is_escalated` predicate)
- Create `auditor/jwtaudit/forge.py` (`none_token`, `hs256_token`, `tamper_claims`, `pubkey_as_hmac_token`)
- Create `auditor/jwtaudit/cracker.py` (`crack_hs256`)
- Create `auditor/jwtaudit/probes/__init__.py`, `auditor/jwtaudit/probes/base.py` (`Probe` ABC + registry)
- Create `auditor/jwtaudit/cli.py` (typer `audit` command: login → baseline → run registered probes (none yet) → placeholder summary)
- Create `auditor/wordlists/common-secrets.txt` (includes planted `secret`)

**How to manually verify before moving on:**
- `pip install -e auditor` → `jwtaudit --help` works.
- Unit: `crack_hs256` finds a planted secret and returns `None` on miss; `is_escalated` true only for 200-with-admin-markers vs. a captured 403 baseline.
- `jwtaudit audit --base-url http://localhost:4000 ...` → logs in as alice, prints captured baseline (admin=403), reports "0 probes registered". No crash.

**Does NOT include:** any probe logic, rich formatting, JSON output, docker. CLI is a scaffold that proves login + baseline + registry wiring.

---

## Phase 4: Probes (each its own sub-phase, in this order)

Every sub-phase: register the probe, then verify against **both** servers (CONFIRMED on vuln where expected, NOT_VULNERABLE on secure).

### Phase 4.1: `none_alg`
- **Files:** Create `auditor/jwtaudit/probes/none_alg.py`; register it.
- **Verify:** vuln → `none_alg` **CONFIRMED** (200 + secret_data, forged token in evidence). secure → **NOT_VULNERABLE** (401). Establishes an `alg:none` forge capability.
- **Excludes:** all other probes; capability plumbing beyond recording the none-primitive.

### Phase 4.2: `weak_secret`
- **Files:** Create `auditor/jwtaudit/probes/weak_secret.py` (uses `cracker.crack_hs256`); register it.
- **Verify:** vuln → **CONFIRMED**, evidence note shows cracked secret `secret`; re-signed `role=admin` token gets 200. secure → **NOT_VULNERABLE** (crack fails, RS256). Records a cracked-secret forge capability.
- **Excludes:** confusion/expiration/bypass logic.

### Phase 4.3: `expiration`
- **Files:** Create `auditor/jwtaudit/probes/expiration.py` (consumes best `ForgeCapability`); wire the **signing-capability summary** line into `cli.py` between Phase A and Phase B.
- **Verify:** vuln → summary prints `Forge capability: GAINED via alg:none`; `expiration` **CONFIRMED** (past-`exp` token still 200). secure → summary prints `NOT GAINED`; `expiration` **NOT_VULNERABLE` (no primitive to mint an accepted token).
- **Excludes:** confusion/bypass probes.

### Phase 4.4: `alg_confusion`
- **Files:** Create `auditor/jwtaudit/probes/alg_confusion.py` (fetch JWKS pubkey, `pubkey_as_hmac_token`); register it.
- **Verify:** vuln → **CONFIRMED** (HS256-signed-with-pubkey token → 200). secure → **NOT_VULNERABLE** (algorithms pinned → 401). If JWKS absent, probe degrades to `SUSPECTED`/skip, never a false CONFIRMED.
- **Excludes:** bypass probe.

### Phase 4.5: `signature_bypass`
- **Files:** Create `auditor/jwtaudit/probes/signature_bypass.py`; register it.
- **Verify:** vuln → **NOT_VULNERABLE** (tampered claims + garbage signature → 401 — the demo's correct-silence moment). secure → **NOT_VULNERABLE**. This proves the auditor is not a false-positive machine.
- **Excludes:** nothing further; probe set complete.

**Phase 4 does NOT include:** report formatting, demo script, pytest, docker (probes verified by eye via the scaffold CLI).

---

## Phase 5: `report.py` + `run_demo.sh`

**Files created/modified:**
- Create `auditor/jwtaudit/report.py` (rich console table + per-CONFIRMED detail blocks + `write_json`)
- Modify `auditor/jwtaudit/cli.py` (call `report.render` and `report.write_json`; exit non-zero if any CONFIRMED)
- Create `run_demo.sh` (audit vuln then secure, write two JSON reports, echo the 4-vs-0 outcome)

**How to manually verify before moving on:**
- `jwtaudit audit --base-url http://localhost:4000 --json-out vuln.json` → colored table with 4 CONFIRMED + 1 NOT_VULNERABLE, signing-capability line between phases, non-zero exit.
- Same against `:4001` → all NOT_VULNERABLE, `NOT GAINED`, exit 0.
- `vuln.json`/`secure.json` summary counts match the table.
- `bash run_demo.sh` → readable end-to-end demo output.

**Does NOT include:** pytest regression, Makefile, docker-compose. Markdown report (deferred).

---

## Phase 6: pytest regression + Makefile + docker-compose

**Files created/modified:**
- Create `tests/conftest.py` (fixtures boot both servers — docker compose or node subprocess — and yield base URLs)
- Create `tests/test_cracker.py`, `tests/test_escalation.py` (unit, no network)
- Create `tests/test_regression.py` (vuln CONFIRMED set == `{none_alg, weak_secret, alg_confusion, expiration}` and `signature_bypass`==NOT_VULNERABLE; secure → zero CONFIRMED, forge capability NOT GAINED)
- Create `docker-compose.yml` (vulnerable-server:4000, secure-server:4001, auditor on demand)
- Create `Makefile` (`up`, `down`, `demo`, `test`), `README.md`

**How to manually verify before moving on:**
- `docker compose up -d` → both servers healthy.
- `make test` → green; regression assertions encode the §1 success criteria.
- `make demo` → the 4-vs-0 demo runs from a clean checkout.

**Does NOT include:** deferred probes (`kid`/`jku`/`jwk`, `nbf`/`iat`, `aud`/`iss`), CI config, Markdown report.

---

## Self-review (plan vs. spec)

- **Spec coverage:** §3 layout → all phases; §4.2 vuln server → P1; §4.3 secure → P2; §5.1 models → P3; §5.2 client/baseline → P3; §5.3 forge/cracker → P3; §5.4 probes → P4.1–4.5; §5.5 flow + signing-capability summary → P4.3 (summary) & P5 (report); §5.6 report → P5; §6 CLI → P3/P5; §7 tests → P6; §8 docker → P6; §9 deferred → excluded throughout. No gaps.
- **Placeholder scan:** none — every phase names concrete files, a verifiable behavior, and an explicit boundary.
- **Consistency:** probe ids, `ForgeCapability`, `is_escalated`, `crack_hs256`, JWKS usage match spec names throughout.

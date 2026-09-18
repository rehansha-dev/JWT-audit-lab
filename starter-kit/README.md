# JWT Audit Lab — Starter Kit

Test your authentication system against the JWT Audit Lab scanner.

## Quick Start

```
npm install
npm start
```

Server runs on http://localhost:4000

## Then open JWT Audit Lab

Set Base URL to: http://localhost:4000
Username: alice
Password: password123
Admin Path: /admin

Click Run Audit.

## Required Endpoints

Your server must expose:

| Endpoint | Method | Description |
|----------|--------|-------------|
| /login | POST | Returns JWT token |
| /me | GET | Returns user identity |
| /admin | GET | Admin-only protected route |

## Request/Response Contract

POST /login
  Body:     { "username": "alice", "password": "password123" }
  Response: { "token": "eyJ..." }

GET /me
  Header:   Authorization: Bearer <token>
  Response: { "username": "alice", "role": "user" }

GET /admin
  Header:   Authorization: Bearer <token>
  Response (allowed): { "secret_data": "...", "role": "admin" }
  Response (blocked): 403 Forbidden

## Vulnerabilities this server contains

This starter kit is DELIBERATELY VULNERABLE for testing:

- V1: alg:none bypass (no signature required)
- V2: Weak HMAC secret (crackable from wordlist)
- V3: Missing expiry check (expired tokens accepted)
- V4: RS256→HS256 confusion (public key as HMAC)
- V5: JWK header injection (CVE-2018-0114)

## For testing YOUR server

Replace this server with your own application.
Keep the same 3 endpoints and test user.
The JWT Audit Lab will find real vulnerabilities
in your implementation.

## Disclaimer

Authorized use only. Only test servers you own.

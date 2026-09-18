// Deliberately vulnerable JWT auth server (authorized security lab).
// Implements the "discriminating broken" middleware from the design spec (§4.2):
// it is exploitable via alg:none, weak HMAC secret, RS256->HS256 confusion, and
// missing expiration checks, but STILL rejects a genuinely bad signature -- so an
// auditor that confirms exploitability can distinguish real bugs from non-bugs.
//
// DO NOT DEPLOY. Every "footgun" comment marks an intentional weakness.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const { PUBLIC_KEY, JWKS } = require('./keys');

// Footgun: a weak, guessable HMAC signing secret (planted in the auditor wordlist).
const WEAK_SECRET = 'secret';
const PORT = process.env.PORT || 4000;

// Seeded identities. The auditor is only ever given alice's credentials.
const USERS = {
  alice: { password: 'password123', role: 'user' },
  admin: { password: 'admin123', role: 'admin' },
};

const app = express();
app.use(express.json());

// ---------------------------------------------------------------------------
// Signature helpers (verification is hand-rolled to model the footguns exactly).
// ---------------------------------------------------------------------------
function b64urlToJson(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

function verifyHmacSha256(signingInput, signatureB64, key) {
  const expected = crypto.createHmac('sha256', key).update(signingInput).digest('base64url');
  const got = Buffer.from(signatureB64);
  const want = Buffer.from(expected);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

function verifyRs256(signingInput, signatureB64, publicKeyPem) {
  try {
    return crypto.verify(
      'RSA-SHA256',
      Buffer.from(signingInput),
      publicKeyPem,
      Buffer.from(signatureB64, 'base64url'),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// The deliberately-vulnerable auth middleware.
// ---------------------------------------------------------------------------
function auth(req, res, next) {
  const authz = req.headers.authorization || '';
  const token = authz.startsWith('Bearer ') ? authz.slice(7).trim() : null;
  if (!token) {
    return res.status(401).json({ error: 'missing bearer token' });
  }

  const parts = token.split('.');
  if (parts.length < 2) {
    return res.status(401).json({ error: 'malformed token' });
  }
  const [headerB64, payloadB64, signatureB64 = ''] = parts;

  let header;
  let payload;
  try {
    header = b64urlToJson(headerB64);
    payload = b64urlToJson(payloadB64);
  } catch {
    return res.status(401).json({ error: 'undecodable token' });
  }

  const alg = header.alg;
  const signingInput = `${headerB64}.${payloadB64}`;

  // V5 CVE-2018-0114 -- trusts attacker-supplied JWK header (footgun)
  // If the token header carries its own "jwk", verify against THAT key instead
  // of the server's trusted key. The attacker signs with their own private key
  // and ships the matching public key in the header, so verification "passes".
  if (header.jwk) {
    try {
      const attackerKey = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
      if (verifyRs256(signingInput, signatureB64, attackerKey)) {
        req.user = payload;
        return next();
      }
    } catch {
      return res.status(401).json({ error: 'bad jwk header' });
    }
    return res.status(401).json({ error: 'invalid jwk signature' });
  }

  // Footgun (all branches): expiration is never checked.
  if (alg === 'none') {
    // Footgun 1 (P1 none_alg): unsigned tokens are trusted.
    req.user = payload;
    return next();
  }

  if (alg === 'HS256') {
    // Footgun 2 (P2 weak_secret) + Footgun 3 (P3 alg_confusion):
    // accept HS256 signed with the weak secret OR with the RSA public key bytes.
    if (
      verifyHmacSha256(signingInput, signatureB64, WEAK_SECRET) ||
      verifyHmacSha256(signingInput, signatureB64, PUBLIC_KEY)
    ) {
      req.user = payload;
      return next();
    }
    // A tampered payload with a bad signature is still rejected (P4 stays silent).
    return res.status(401).json({ error: 'invalid HS256 signature' });
  }

  if (alg === 'RS256') {
    if (verifyRs256(signingInput, signatureB64, PUBLIC_KEY)) {
      req.user = payload;
      return next();
    }
    return res.status(401).json({ error: 'invalid RS256 signature' });
  }

  return res.status(401).json({ error: `unsupported alg: ${alg}` });
}

// ---------------------------------------------------------------------------
// Routes.
// ---------------------------------------------------------------------------
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const record = USERS[username];
  if (!record || record.password !== password) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  // Footgun: tokens are signed HS256 with the weak secret.
  const token = jwt.sign(
    { sub: username, username, role: record.role },
    WEAK_SECRET,
    { algorithm: 'HS256', expiresIn: '15m' },
  );
  return res.json({ token });
});

app.get('/me', auth, (req, res) => {
  return res.json({ username: req.user.username, role: req.user.role });
});

app.get('/admin', auth, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden: admin role required' });
  }
  return res.json({ secret_data: 'FLAG{vulnerable-jwt-admin-access}', role: 'admin' });
});

app.get('/.well-known/jwks.json', (req, res) => {
  return res.json({ keys: [JWKS] });
});

app.listen(PORT, () => {
  console.log(`[vulnerable-server] listening on http://localhost:${PORT}`);
});

module.exports = app;

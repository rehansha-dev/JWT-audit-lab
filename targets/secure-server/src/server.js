// Correctly hardened JWT auth server (authorized security lab reference target).
// Signs and verifies with RS256 ONLY, pins the algorithm, enforces expiration, and
// gates /admin on the verified role claim. There is no HMAC secret anywhere, so
// nothing to crack and no algorithm to confuse. A black-box auditor should find
// ZERO exploitable weaknesses here.
const express = require('express');
const jwt = require('jsonwebtoken');

const { PRIVATE_KEY, PUBLIC_KEY, JWKS, KID } = require('./keys');

const PORT = process.env.PORT || 4001;

// Seeded identities. The auditor is only ever given alice's credentials.
const USERS = {
  alice: { password: 'password123', role: 'user' },
  admin: { password: 'admin123', role: 'admin' },
};

const app = express();
app.use(express.json());

// ---------------------------------------------------------------------------
// Hardened auth middleware: RS256 pinned, signature + expiration enforced.
// ---------------------------------------------------------------------------
function auth(req, res, next) {
  const authz = req.headers.authorization || '';
  const token = authz.startsWith('Bearer ') ? authz.slice(7).trim() : null;
  if (!token) {
    return res.status(401).json({ error: 'missing bearer token' });
  }
  try {
    // Pinning algorithms to ['RS256'] rejects alg:none and HS256 confusion.
    // Expiration is enforced by default (no ignoreExpiration).
    const claims = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
    req.user = claims;
    return next();
  } catch {
    return res.status(401).json({ error: 'invalid token' });
  }
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
  const token = jwt.sign(
    { sub: username, username, role: record.role },
    PRIVATE_KEY,
    { algorithm: 'RS256', expiresIn: '15m', keyid: KID },
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
  return res.json({ secret_data: 'admin-only-data', role: 'admin' });
});

app.get('/.well-known/jwks.json', (req, res) => {
  return res.json({ keys: [JWKS] });
});

app.listen(PORT, () => {
  console.log(`[secure-server] listening on http://localhost:${PORT}`);
});

module.exports = app;

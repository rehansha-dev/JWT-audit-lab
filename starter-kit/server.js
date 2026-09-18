const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();
app.use(express.json());

const WEAK_SECRET = 'secret';

const USERS = [
  { id: 1, username: 'alice', password: 'password123', role: 'user' },
  { id: 2, username: 'admin', password: 'hunter2',    role: 'admin' },
];

// Generate RSA keypair on start
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// JWKS endpoint — exposes public key
app.get('/.well-known/jwks.json', (req, res) => {
  const pubKeyObj = crypto.createPublicKey(publicKey);
  const exported = pubKeyObj.export({ format: 'jwk' });
  res.json({ keys: [{ ...exported, kty: 'RSA', use: 'sig', kid: 'kit-key-1' }] });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    WEAK_SECRET,
    { algorithm: 'HS256' }
  );
  res.json({ token });
});

// Auth middleware — deliberately broken (all 5 flaws)
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token' });

  const token = auth.slice(7);

  try {
    const parts = token.split('.');
    if (parts.length !== 3)
      return res.status(401).json({ error: 'Bad token format' });

    const header = JSON.parse(
      Buffer.from(parts[0], 'base64url').toString()
    );

    // V1: alg:none accepted
    if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
      const payload = JSON.parse(
        Buffer.from(parts[1], 'base64url').toString()
      );
      req.user = payload;
      return next();
    }

    // V5: JWK header injection (CVE-2018-0114)
    if (header.jwk) {
      try {
        const attackerKey = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
        const payload = jwt.verify(token, attackerKey, { algorithms: ['RS256'] });
        req.user = payload;
        return next();
      } catch {}
    }

    // V4: RS256 -> HS256 confusion (pubkey as HMAC)
    // V2: weak HMAC secret
    // V3: ignoreExpiration
    const payload = jwt.verify(token, WEAK_SECRET, {
      algorithms: ['HS256'],
      ignoreExpiration: true,
    });
    req.user = payload;
    next();

  } catch (err) {
    // Try with public key as HMAC (alg confusion)
    try {
      const payload = jwt.verify(token, publicKey, {
        algorithms: ['HS256'],
        ignoreExpiration: true,
      });
      req.user = payload;
      next();
    } catch {
      res.status(401).json({ error: 'Invalid token' });
    }
  }
}

// GET /me — returns caller identity
app.get('/me', authenticate, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// GET /admin — admin only
app.get('/admin', authenticate, (req, res) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Admin only' });
  res.json({
    secret_data: 'FLAG{jwt-audit-lab-pwned}',
    role: 'admin',
    message: 'You have admin access via JWT vulnerability'
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', flaws: 'V1-V5 active' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log('');
  console.log('  JWT Audit Lab — Vulnerable Server');
  console.log('  ──────────────────────────────────');
  console.log(`  Running on http://localhost:${PORT}`);
  console.log('');
  console.log('  Endpoints:');
  console.log(`    POST http://localhost:${PORT}/login`);
  console.log(`    GET  http://localhost:${PORT}/me`);
  console.log(`    GET  http://localhost:${PORT}/admin`);
  console.log(`    GET  http://localhost:${PORT}/.well-known/jwks.json`);
  console.log('');
  console.log('  Test credentials:');
  console.log('    username: alice    password: password123');
  console.log('    username: admin    password: hunter2');
  console.log('');
  console.log('  Point JWT Audit Lab at: http://localhost:4000');
  console.log('');
});

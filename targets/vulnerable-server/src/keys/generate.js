// Generates a dev-only RSA keypair for the vulnerable server.
// Keys are lab-only, git-ignored, and regenerated if missing. Never reuse in production.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DIR = __dirname;
const PRIVATE_PEM = path.join(DIR, 'private.pem');
const PUBLIC_PEM = path.join(DIR, 'public.pem');

function generate() {
  if (fs.existsSync(PRIVATE_PEM) && fs.existsSync(PUBLIC_PEM)) {
    return;
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(PRIVATE_PEM, privateKey);
  fs.writeFileSync(PUBLIC_PEM, publicKey);
  console.log('[keys] generated dev RSA keypair');
}

generate();

module.exports = { generate, PRIVATE_PEM, PUBLIC_PEM };

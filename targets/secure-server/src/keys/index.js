// Loads the dev RSA keypair and derives its JWKS representation.
// The secure server signs and verifies with RS256 only; the public key is published
// so a black-box auditor can attempt (and fail) an RS256->HS256 confusion attack.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

require('./generate'); // ensure keys exist before we read them

const DIR = __dirname;
const KID = 'secure-key-1';
const PRIVATE_KEY = fs.readFileSync(path.join(DIR, 'private.pem'), 'utf8');
const PUBLIC_KEY = fs.readFileSync(path.join(DIR, 'public.pem'), 'utf8');

const publicKeyObject = crypto.createPublicKey(PUBLIC_KEY);
const jwk = publicKeyObject.export({ format: 'jwk' }); // { kty, n, e }

const JWKS = { ...jwk, kid: KID, use: 'sig', alg: 'RS256' };

module.exports = { PRIVATE_KEY, PUBLIC_KEY, JWKS, KID };

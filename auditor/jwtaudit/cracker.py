"""Offline HS256 secret brute-force. Pure and network-free."""

from __future__ import annotations

import base64
import hashlib
import hmac
from pathlib import Path
from typing import Optional

# Resolve the bundled wordlist relative to the package so `jwtaudit` works from
# any working directory, not just auditor/.
DEFAULT_WORDLIST: Path = Path(__file__).parent.parent / "wordlists" / "common-secrets.txt"


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def crack_hs256(token: str, wordlist_path: str | Path = DEFAULT_WORDLIST) -> Optional[str]:
    """Return the first wordlist entry whose HS256 signature matches the token.

    Recomputes the HMAC-SHA256 of the token's signing input for each candidate
    and compares against the token's signature. Returns None if nothing matches
    or the token is not a well-formed three-part JWT.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        target_signature = _b64url_decode(signature_b64)
    except (ValueError, TypeError):
        return None

    path = Path(wordlist_path)
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            candidate = line.strip()
            if not candidate:
                continue
            computed = hmac.new(
                candidate.encode("utf-8"), signing_input, hashlib.sha256
            ).digest()
            if hmac.compare_digest(computed, target_signature):
                return candidate
    return None

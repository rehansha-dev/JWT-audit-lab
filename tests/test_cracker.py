"""Unit tests for the offline HS256 cracker. No network."""

from __future__ import annotations

from jwtaudit.cracker import DEFAULT_WORDLIST, crack_hs256
from jwtaudit.forge import hs256_token

_CLAIMS = {"sub": "alice", "username": "alice", "role": "user"}


def test_cracks_known_secret() -> None:
    # 'secret' is present in the bundled wordlist.
    token = hs256_token(_CLAIMS, "secret")
    assert crack_hs256(token, DEFAULT_WORDLIST) == "secret"


def test_unknown_secret_returns_none() -> None:
    token = hs256_token(_CLAIMS, "ZZZUNKNOWN")
    assert crack_hs256(token, DEFAULT_WORDLIST) is None

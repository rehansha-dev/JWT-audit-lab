"""Unit tests for the CONFIRMED escalation gate (is_escalated). No network."""

from __future__ import annotations

import httpx

from jwtaudit.client import AuthClient, Baseline
from jwtaudit.models import Target


def _client() -> AuthClient:
    target = Target(
        base_url="http://localhost:0",
        login_path="/login",
        protected_path="/me",
        admin_path="/admin",
        username="alice",
        password="password123",
    )
    return AuthClient(target)


def _baseline() -> Baseline:
    return Baseline(
        token="x",
        role="user",
        me_status=200,
        me_body={"username": "alice", "role": "user"},
        admin_status=403,
        admin_snippet="",
    )


def test_confirmed_on_200_with_marker() -> None:
    client = _client()
    resp = httpx.Response(200, json={"secret_data": "FLAG{x}", "role": "admin"})
    assert client.is_escalated(resp, _baseline()) is True
    client.close()


def test_not_confirmed_on_403() -> None:
    client = _client()
    resp = httpx.Response(403, json={"error": "forbidden"})
    assert client.is_escalated(resp, _baseline()) is False
    client.close()


def test_not_confirmed_on_200_no_marker() -> None:
    client = _client()
    resp = httpx.Response(200, json={"username": "alice", "role": "user"})
    assert client.is_escalated(resp, _baseline()) is False
    client.close()

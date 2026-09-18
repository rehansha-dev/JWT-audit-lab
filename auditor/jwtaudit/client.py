"""HTTP client, baseline capture, and the black-box escalation predicate."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from .models import Target


@dataclass
class Baseline:
    """What a legitimate normal-user session can and cannot reach.

    Every CONFIRMED verdict is measured against this, so the auditor never has
    to know server internals to prove escalation.
    """

    token: str
    role: Optional[str]
    me_status: int
    me_body: dict[str, Any] = field(default_factory=dict)
    admin_status: int = 0
    admin_snippet: str = ""


class AuthClient:
    """Thin httpx wrapper exposing only what a black-box auditor needs."""

    def __init__(self, target: Target, timeout: float = 10.0) -> None:
        self.target = target
        self._client = httpx.Client(base_url=target.base_url, timeout=timeout)

    def login(self) -> str:
        resp = self._client.post(
            self.target.login_path,
            json={"username": self.target.username, "password": self.target.password},
        )
        resp.raise_for_status()
        token = resp.json().get("token")
        if not token:
            raise RuntimeError("login succeeded but returned no token")
        return token

    def get(self, path: str, token: Optional[str]) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self._client.get(path, headers=headers)

    def capture_baseline(self) -> Baseline:
        token = self.login()
        me = self.get(self.target.protected_path, token)
        admin = self.get(self.target.admin_path, token)
        role: Optional[str] = None
        me_body: dict[str, Any] = {}
        try:
            me_body = me.json()
            role = me_body.get("role")
        except ValueError:
            pass
        return Baseline(
            token=token,
            role=role,
            me_status=me.status_code,
            me_body=me_body,
            admin_status=admin.status_code,
            admin_snippet=admin.text[:200],
        )

    def is_escalated(self, resp: httpx.Response, baseline: Baseline) -> bool:
        """The CONFIRMED gate.

        True only when the response is HTTP 200 AND reveals identity or data the
        baseline normal-user provably could not reach: admin markers on an
        endpoint that denied the baseline user, or a role escalated to admin.
        """
        if resp.status_code != 200:
            return False
        try:
            data = resp.json()
        except ValueError:
            return False
        if not isinstance(data, dict):
            return False

        got_admin_markers = data.get("role") == "admin" or "secret_data" in data

        # Case 1: reached admin data the baseline user was denied.
        if baseline.admin_status != 200 and got_admin_markers:
            return True

        # Case 2: identity escalated from a non-admin baseline role to admin.
        if baseline.role and baseline.role != "admin" and data.get("role") == "admin":
            return True

        return False

    def close(self) -> None:
        self._client.close()

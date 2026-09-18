"""P5: expiration (exp) not enforced.

Capability-dependent (Phase B): reuses the forge capability established by the
Phase A probes to mint an otherwise-acceptable token whose `exp` is in the past,
then checks whether the protected endpoint still serves it.
"""

from __future__ import annotations

import time
from typing import Any

from ..client import AuthClient, Baseline
from ..models import Evidence, Finding, ForgeCapability, Severity, Target, Verdict
from .base import Probe, register


class ExpirationProbe(Probe):
    id = "expiration"
    title = "expired token accepted (exp not enforced)"
    severity = Severity.HIGH
    cwe = "CWE-613"
    requires_capability = True
    remediation = (
        "Enforce the 'exp' claim on every request and reject expired tokens "
        "(never set ignoreExpiration). Keep token lifetimes short and validate "
        "'exp', 'nbf', and 'iat' during verification."
    )

    def run(
        self,
        client: AuthClient,
        target: Target,
        baseline: Baseline,
        capability: ForgeCapability,
    ) -> Finding:
        request_line = f"GET {target.protected_path}"

        if not capability.gained or capability.mint is None:
            evidence = Evidence(
                forged_token=None,
                request_line=request_line,
                status_code=None,
                response_snippet="",
                note="SKIPPED (no signing capability)",
            )
            return self._finding(Verdict.SKIPPED, evidence)

        past_exp = int(time.time()) - 3600  # one hour in the past
        claims: dict[str, Any] = {"role": "user", "exp": past_exp}
        forged = capability.mint(claims)
        resp = client.get(target.protected_path, forged)
        snippet = resp.text[:200]

        # An expired token that should be rejected but still returns protected data.
        if resp.status_code == 200:
            evidence = Evidence(
                forged_token=forged,
                request_line=request_line,
                status_code=resp.status_code,
                response_snippet=snippet,
                note=f"expired token (exp={past_exp}, 1h in the past) accepted on {target.protected_path}",
            )
            return self._finding(Verdict.CONFIRMED, evidence)

        evidence = Evidence(
            forged_token=forged,
            request_line=request_line,
            status_code=resp.status_code,
            response_snippet=snippet,
            note="expired token rejected",
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


register(ExpirationProbe())

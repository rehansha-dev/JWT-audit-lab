"""P4: signature integrity (tampered claims, original signature).

Takes the legitimate token, flips role -> admin, and keeps the ORIGINAL signature
(no re-signing). Any server that verifies signatures rejects this, so the expected
verdict on BOTH targets is NOT_VULNERABLE. The whole point of this probe is to prove
the auditor does not false-positive: it only reports CONFIRMED if a tampered,
wrongly-signed token genuinely yields escalated access (HTTP 200 + escalation).
"""

from __future__ import annotations

from ..client import AuthClient, Baseline
from ..forge import tamper_claims
from ..models import Evidence, Finding, ForgeCapability, Severity, Target, Verdict
from .base import Probe, register


class SignatureBypassProbe(Probe):
    id = "signature_bypass"
    title = "signature integrity"
    severity = Severity.CRITICAL
    cwe = "CWE-347"
    remediation = (
        "Always verify the token signature before trusting any claim. Reject tokens "
        "whose signature does not match the payload; never read claims from an "
        "unverified or decode-only token."
    )

    def run(
        self,
        client: AuthClient,
        target: Target,
        baseline: Baseline,
        capability: ForgeCapability,
    ) -> Finding:
        request_line = f"GET {target.admin_path}"
        # Flip role to admin but keep the original (now-invalid) signature.
        forged = tamper_claims(baseline.token, {"role": "admin"})
        resp = client.get(target.admin_path, forged)
        snippet = resp.text[:200]

        if client.is_escalated(resp, baseline):
            # Would be a genuine new bug: claims trusted without signature check.
            evidence = Evidence(
                forged_token=forged,
                request_line=request_line,
                status_code=resp.status_code,
                response_snippet=snippet,
                note="tampered payload with the original signature was accepted",
            )
            return self._finding(Verdict.CONFIRMED, evidence)

        evidence = Evidence(
            forged_token=forged,
            request_line=request_line,
            status_code=resp.status_code,
            response_snippet=snippet,
            note="tampered token rejected; signature integrity enforced (expected)",
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


register(SignatureBypassProbe())

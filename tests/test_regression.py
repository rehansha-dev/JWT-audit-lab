"""End-to-end regression: run all probes against both live servers (needs Node)."""

from __future__ import annotations

from jwtaudit.client import AuthClient
from jwtaudit.models import Finding, ForgeCapability, Target, Verdict
from jwtaudit.runner import run_probes


def _audit(base_url: str) -> tuple[list[Finding], ForgeCapability]:
    target = Target(
        base_url=base_url,
        login_path="/login",
        protected_path="/me",
        admin_path="/admin",
        username="alice",
        password="password123",
    )
    client = AuthClient(target)
    try:
        baseline = client.capture_baseline()
        return run_probes(client, target, baseline)
    finally:
        client.close()


def _confirmed(findings: list[Finding]) -> set[str]:
    return {f.probe_id for f in findings if f.verdict == Verdict.CONFIRMED}


def _not_vulnerable(findings: list[Finding]) -> set[str]:
    return {f.probe_id for f in findings if f.verdict == Verdict.NOT_VULNERABLE}


def _would_exit(findings: list[Finding]) -> int:
    return 1 if any(f.verdict == Verdict.CONFIRMED for f in findings) else 0


def test_vulnerable_confirmed_set(vulnerable_server: str) -> None:
    findings, _ = _audit(vulnerable_server)
    assert _confirmed(findings) == {"none_alg", "weak_secret", "alg_confusion", "expiration"}


def test_vulnerable_not_vulnerable_set(vulnerable_server: str) -> None:
    findings, _ = _audit(vulnerable_server)
    assert _not_vulnerable(findings) == {"signature_bypass"}


def test_secure_zero_confirmed(secure_server: str) -> None:
    findings, _ = _audit(secure_server)
    assert _confirmed(findings) == set()


def test_exit_codes(vulnerable_server: str, secure_server: str) -> None:
    vuln_findings, _ = _audit(vulnerable_server)
    secure_findings, _ = _audit(secure_server)
    assert _would_exit(vuln_findings) == 1
    assert _would_exit(secure_findings) == 0

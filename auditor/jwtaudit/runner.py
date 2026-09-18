"""Probe orchestration: run Phase A (forgery primitives) then Phase B (dependent)."""

from __future__ import annotations

from typing import Callable, Optional

from .client import AuthClient, Baseline
from .models import Finding, ForgeCapability, Target, Verdict
from .probes.base import all_probes

# Optional per-probe observer: called once after each probe completes, with the
# finding and the capability as it stands at that moment. Purely for live
# reporting (e.g. streaming to a UI); it never affects the audit result.
OnFinding = Callable[[Finding, ForgeCapability], None]


def run_probes(
    client: AuthClient,
    target: Target,
    baseline: Baseline,
    on_finding: Optional[OnFinding] = None,
) -> tuple[list[Finding], ForgeCapability]:
    """Run every registered probe and return the findings plus the forge capability.

    Phase A (forgery-primitive) probes run first; the first CONFIRMED one to grant
    a capability wins (registration order). Phase B (capability-dependent) probes
    run afterwards with that capability.

    If ``on_finding`` is given it is invoked after each probe completes with
    ``(finding, capability)``. It is optional and side-effect-only, so existing
    callers (CLI, tests) are unaffected.
    """
    registered = all_probes()
    phase_a = [p for p in registered if not p.requires_capability]
    phase_b = [p for p in registered if p.requires_capability]

    capability = ForgeCapability(gained=False)
    findings: list[Finding] = []

    for probe in phase_a:
        finding = probe.run(client, target, baseline, capability)
        findings.append(finding)
        if finding.verdict == Verdict.CONFIRMED and not capability.gained:
            granted = probe.forge_capability()
            if granted is not None:
                capability = granted
        if on_finding is not None:
            on_finding(finding, capability)

    for probe in phase_b:
        finding = probe.run(client, target, baseline, capability)
        findings.append(finding)
        if on_finding is not None:
            on_finding(finding, capability)

    return findings, capability

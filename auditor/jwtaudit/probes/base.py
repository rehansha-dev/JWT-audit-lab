"""Probe abstract base class and a simple import-time registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..client import AuthClient, Baseline
from ..models import Finding, ForgeCapability, Severity, Target


class Probe(ABC):
    """One attack class. Implementations set the class attributes and run()."""

    id: str
    title: str
    severity: Severity
    cwe: str
    remediation: str
    # Phase B probes (True) run after the signing-capability summary and depend
    # on a ForgeCapability; Phase A forgery-primitive probes (False) run first.
    requires_capability: bool = False

    @abstractmethod
    def run(
        self,
        client: AuthClient,
        target: Target,
        baseline: Baseline,
        capability: ForgeCapability,
    ) -> Finding:
        """Forge a token, send it, and return a structured Finding."""
        raise NotImplementedError

    def forge_capability(self) -> Optional[ForgeCapability]:
        """The forge capability this probe grants once CONFIRMED, if any.

        Forgery-primitive probes (none/weak-secret/confusion) override this so
        the runner can arm capability-dependent probes. Returns None by default.
        """
        return None


_REGISTRY: list[Probe] = []


def register(probe: Probe) -> Probe:
    """Register a probe instance (called at import time by each probe module)."""
    _REGISTRY.append(probe)
    return probe


def all_probes() -> list[Probe]:
    """Return every registered probe, in registration order."""
    return list(_REGISTRY)

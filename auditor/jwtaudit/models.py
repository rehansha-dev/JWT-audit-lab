"""Core data model: findings, verdicts, target config, and forge capability."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from .cracker import DEFAULT_WORDLIST


class Verdict(str, Enum):
    """Outcome of a probe. CONFIRMED requires empirical escalation, never a hint."""

    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Target:
    """Everything the black-box auditor is allowed to know about a target.

    Plus the auditor's own per-run inputs (credentials, wordlist path). None of
    this is server-internal knowledge.
    """

    base_url: str
    login_path: str
    protected_path: str
    admin_path: str
    username: str
    password: str
    wordlist_path: str = str(DEFAULT_WORDLIST)


@dataclass
class Evidence:
    """Concrete proof attached to every finding."""

    forged_token: Optional[str]
    request_line: str
    status_code: Optional[int]
    response_snippet: str
    note: str = ""


@dataclass
class Finding:
    probe_id: str
    title: str
    verdict: Verdict
    severity: Severity
    cwe: str
    evidence: Evidence
    remediation: str


@dataclass
class ForgeCapability:
    """Whether the auditor can mint a token the target will accept, and how.

    Produced by the forgery-primitive probes and consumed by the
    capability-dependent probes (e.g. expiration).
    """

    gained: bool
    method: Optional[str] = None  # "alg:none" | "weak_secret" | "rs256->hs256-confusion"
    detail: str = ""
    secret: Optional[str] = None  # the recovered HMAC secret, when method == "weak_secret"
    mint: Optional[Callable[[dict[str, Any]], str]] = None

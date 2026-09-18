"""Reporting: a rich console table + detail blocks, and a JSON report file."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console
from rich.table import Table

from .models import Finding, ForgeCapability, Target, Verdict

_ROW_STYLE: dict[Verdict, str] = {
    Verdict.CONFIRMED: "red",
    Verdict.NOT_VULNERABLE: "green",
    Verdict.SKIPPED: "dim",
    Verdict.SUSPECTED: "yellow",
    Verdict.ERROR: "magenta",
}

_TOKEN_LIMIT = 60


def capability_text(capability: ForgeCapability) -> str:
    """Human/JSON string for the signing capability (attack-chain narrative)."""
    if not capability.gained:
        return "NOT ESTABLISHED"
    if capability.method == "weak_secret" and capability.secret:
        return f"GAINED via weak_secret (secret='{capability.secret}')"
    return f"GAINED via {capability.method}"


def _truncate_token(token: Optional[str]) -> Optional[str]:
    if token is None:
        return None
    if len(token) <= _TOKEN_LIMIT:
        return token
    return token[:_TOKEN_LIMIT] + "...(truncated)"


def render(
    console: Console,
    findings: Sequence[Finding],
    capability: ForgeCapability,
    target: Target,
) -> None:
    """Print the findings table, capability line, count summary, and CONFIRMED detail."""
    table = Table(show_header=True, header_style="bold", title=f"JWT audit - {target.base_url}")
    table.add_column("Probe", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("CWE", no_wrap=True)
    table.add_column("Summary")

    for finding in findings:
        style = _ROW_STYLE.get(finding.verdict, "white")
        table.add_row(
            finding.probe_id,
            finding.verdict.value,
            finding.severity.value,
            finding.cwe,
            finding.evidence.note,
            style=style,
        )
    console.print(table)

    console.print(f"[bold]Signing capability:[/bold] {capability_text(capability)}")

    confirmed = [f for f in findings if f.verdict == Verdict.CONFIRMED]
    console.print(f"[bold]{len(confirmed)} CONFIRMED / {len(findings)} probes run[/bold]")

    if confirmed:
        console.rule("[bold red]CONFIRMED detail[/bold red]")
        for finding in confirmed:
            ev = finding.evidence
            console.print(
                f"[bold red]{finding.probe_id}[/bold red] "
                f"({finding.severity.value}, {finding.cwe}) - {finding.evidence.request_line} "
                f"-> {ev.status_code}"
            )
            console.print(f"    forged token: {_truncate_token(ev.forged_token)}")
            console.print(f"    response:     {ev.response_snippet}")
            console.print(f"    remediation:  {finding.remediation}")


def build_report(
    findings: Sequence[Finding],
    capability: ForgeCapability,
    target: Target,
) -> dict:
    """Assemble the JSON-serializable report structure."""
    confirmed = sum(1 for f in findings if f.verdict == Verdict.CONFIRMED)
    return {
        "target": target.base_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signing_capability": capability_text(capability),
        "summary": {"confirmed": confirmed, "total": len(findings)},
        "findings": [
            {
                "probe": f.probe_id,
                "verdict": f.verdict.value,
                "severity": f.severity.value,
                "cwe": f.cwe,
                "evidence": {
                    "forged_token": _truncate_token(f.evidence.forged_token),
                    "response_snippet": f.evidence.response_snippet,
                    "http_status": f.evidence.status_code,
                },
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }


def write_json(
    path: str | Path,
    findings: Sequence[Finding],
    capability: ForgeCapability,
    target: Target,
) -> Path:
    """Write the JSON report to `path` and return the resolved path."""
    report = build_report(findings, capability, target)
    out_path = Path(path)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return out_path

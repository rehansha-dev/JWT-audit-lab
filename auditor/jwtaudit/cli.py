"""Typer CLI: login, capture baseline, run all probes, render report + JSON."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from . import report
from .client import AuthClient
from .cracker import DEFAULT_WORDLIST
from .models import Target, Verdict
from .probes.base import all_probes
from .runner import run_probes

app = typer.Typer(add_completion=False)
console = Console()


@app.callback()
def _root() -> None:
    """Black-box JWT auth attack-surface auditor (authorized security lab)."""


@app.command()
def audit(
    base_url: str = typer.Option(..., "--base-url", help="Target base URL, e.g. http://localhost:4000"),
    login_path: str = typer.Option("/login", "--login-path"),
    protected_path: str = typer.Option("/me", "--protected-path"),
    admin_path: str = typer.Option("/admin", "--admin-path"),
    username: str = typer.Option("alice", "--username"),
    password: str = typer.Option("password123", "--password"),
    wordlist: Optional[str] = typer.Option(
        None, "--wordlist", help="Wordlist for the HMAC cracker (defaults to the bundled list)"
    ),
    json_out: str = typer.Option("report.json", "--json-out", help="Path for the JSON report"),
) -> None:
    """Audit a target's JWT auth attack surface."""
    target = Target(
        base_url=base_url,
        login_path=login_path,
        protected_path=protected_path,
        admin_path=admin_path,
        username=username,
        password=password,
        wordlist_path=wordlist or str(DEFAULT_WORDLIST),
    )
    client = AuthClient(target)

    console.rule("[bold]Baseline capture[/bold]")
    try:
        baseline = client.capture_baseline()
    except Exception as exc:  # noqa: BLE001 - surface any connectivity/login failure
        console.print(f"[red]Failed to capture baseline:[/red] {exc}")
        client.close()
        raise typer.Exit(code=2)

    console.print(f"Target:            {base_url}")
    console.print(f"Login user:        {username}  (role={baseline.role})")
    console.print(f"GET {protected_path}:           {baseline.me_status}  {baseline.me_body}")
    console.print(
        f"GET {admin_path}:        {baseline.admin_status}  "
        f"(normal user {'DENIED' if baseline.admin_status != 200 else 'ALLOWED'})"
    )

    registered = all_probes()
    if not registered:
        console.print("0 probes registered")
        client.close()
        return

    findings, capability = run_probes(client, target, baseline)
    client.close()

    console.rule("[bold]Report[/bold]")
    report.render(console, findings, capability, target)

    written = report.write_json(json_out, findings, capability, target)
    console.print(f"[dim]JSON report written to {written}[/dim]")

    if any(f.verdict == Verdict.CONFIRMED for f in findings):
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

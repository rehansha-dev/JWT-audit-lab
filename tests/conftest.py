"""Pytest fixtures: boot the two Node target servers as subprocesses."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
VULN_DIR = ROOT / "targets" / "vulnerable-server"
SECURE_DIR = ROOT / "targets" / "secure-server"

# Make `import jwtaudit` work even without `pip install -e auditor`.
AUDITOR_DIR = ROOT / "auditor"
if str(AUDITOR_DIR) not in sys.path:
    sys.path.insert(0, str(AUDITOR_DIR))

_NODE = shutil.which("node") or "node"
_CREDS = {"username": "alice", "password": "password123"}


def _wait_for_login(base_url: str, proc: subprocess.Popen, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"server exited early (code {proc.returncode}) before ready")
        try:
            resp = httpx.post(f"{base_url}/login", json=_CREDS, timeout=1.0)
            if resp.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise TimeoutError(f"server at {base_url} did not respond to /login within {timeout}s")


def _boot(server_dir: Path, port: int) -> tuple[subprocess.Popen, str]:
    env = {**os.environ, "PORT": str(port)}
    proc = subprocess.Popen(
        [_NODE, "src/server.js"],
        cwd=str(server_dir),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base_url = f"http://localhost:{port}"
    try:
        _wait_for_login(base_url, proc)
    except Exception:
        _stop(proc)
        raise
    return proc, base_url


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def vulnerable_server() -> Iterator[str]:
    proc, base_url = _boot(VULN_DIR, 4000)
    try:
        yield base_url
    finally:
        _stop(proc)


@pytest.fixture(scope="session")
def secure_server() -> Iterator[str]:
    proc, base_url = _boot(SECURE_DIR, 4001)
    try:
        yield base_url
    finally:
        _stop(proc)

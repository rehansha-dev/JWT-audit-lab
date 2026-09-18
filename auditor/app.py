"""FastAPI backend for the JWT Audit Lab web UI.

Wraps the existing ``jwtaudit`` package. It runs the real audit in a background
thread and streams each probe result over a WebSocket the moment it completes,
using the optional ``on_finding`` callback of :func:`jwtaudit.runner.run_probes`.

Run from the ``auditor`` directory::

    cd auditor && uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import queue
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from jwtaudit.client import AuthClient
from jwtaudit.models import Finding, ForgeCapability, Target, Verdict
from jwtaudit.probes.base import all_probes
from jwtaudit.report import capability_text
from jwtaudit.runner import run_probes

FORGED_TOKEN_PREVIEW = 80  # chars streamed over the WS (report keeps the full token)

app = FastAPI(title="JWT Audit Lab API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store. Each job carries a thread-safe queue that the worker
# thread fills and the WebSocket drains, so no event is lost if the socket
# connects a moment after the audit starts.
jobs: dict[str, dict[str, Any]] = {}


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class AuditRequest(BaseModel):
    base_url: str = "http://localhost:4000"
    username: str = "alice"
    password: str = "password123"
    admin_path: str = "/admin"


class DecodeRequest(BaseModel):
    token: str


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _cve_by_probe() -> dict[str, Optional[str]]:
    return {p.id: getattr(p, "cve", None) for p in all_probes()}


def _finding_full(finding: Finding, cve: Optional[str]) -> dict[str, Any]:
    """Full finding dict (untruncated token) for the downloadable report."""
    ev = finding.evidence
    return {
        "probe": finding.probe_id,
        "title": finding.title,
        "verdict": finding.verdict.value,
        "severity": finding.severity.value,
        "cwe": finding.cwe,
        "cve": cve,
        "summary": ev.note,
        "evidence": {
            "forged_token": ev.forged_token,
            "response": ev.response_snippet,
            "http_status": ev.status_code,
            "request_line": ev.request_line,
        },
        "remediation": finding.remediation,
    }


def _probe_message(full: dict[str, Any]) -> dict[str, Any]:
    """WebSocket 'probe_result' message: same as the full dict but token-truncated."""
    token = full["evidence"]["forged_token"]
    preview = None
    if token is not None:
        preview = token if len(token) <= FORGED_TOKEN_PREVIEW else token[:FORGED_TOKEN_PREVIEW] + "…"
    msg = {
        "type": "probe_result",
        "probe": full["probe"],
        "title": full["title"],
        "verdict": full["verdict"],
        "severity": full["severity"],
        "cwe": full["cwe"],
        "cve": full["cve"],
        "summary": full["summary"],
        "evidence": {
            "forged_token": preview,
            "response": full["evidence"]["response"],
            "http_status": full["evidence"]["http_status"],
        },
        "remediation": full["remediation"],
    }
    return msg


# --------------------------------------------------------------------------- #
# Background audit worker
# --------------------------------------------------------------------------- #
def _run_audit(job_id: str, target: Target) -> None:
    job = jobs[job_id]
    q: queue.Queue = job["queue"]
    cve_map = _cve_by_probe()

    phase_a_total = sum(1 for p in all_probes() if not p.requires_capability)
    emitted = {"count": 0}

    def on_finding(finding: Finding, capability: ForgeCapability) -> None:
        full = _finding_full(finding, cve_map.get(finding.probe_id))
        job["findings"].append(full)
        q.put(_probe_message(full))
        emitted["count"] += 1
        # Capability is final once every Phase A (forgery-primitive) probe has run.
        if emitted["count"] == phase_a_total:
            cap_text = capability_text(capability)
            job["capability"] = cap_text
            q.put({"type": "capability", "signing_capability": cap_text})

    client: Optional[AuthClient] = None
    try:
        client = AuthClient(target)
        baseline = client.capture_baseline()
        findings, capability = run_probes(client, target, baseline, on_finding=on_finding)

        confirmed = sum(1 for f in findings if f.verdict == Verdict.CONFIRMED)
        summary = {
            "confirmed": confirmed,
            "total": len(findings),
            "exit_code": 1 if confirmed else 0,
        }
        job["summary"] = summary
        job["capability"] = capability_text(capability)
        job["status"] = "complete"
        q.put({"type": "complete", "summary": summary})
    except Exception as exc:  # noqa: BLE001 - surface any connectivity/login failure
        job["status"] = "error"
        job["error"] = f"{type(exc).__name__}: {exc}"
        q.put({"type": "error", "message": job["error"]})
    finally:
        if client is not None:
            client.close()
        q.put(None)  # sentinel: end of stream


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@app.post("/api/audit/start")
def start_audit(req: AuditRequest) -> dict[str, str]:
    job_id = str(uuid.uuid4())
    target = Target(
        base_url=req.base_url.rstrip("/"),
        login_path="/login",
        protected_path="/me",
        admin_path=req.admin_path,
        username=req.username,
        password=req.password,
    )
    jobs[job_id] = {
        "status": "running",
        "target": target,
        "queue": queue.Queue(),
        "findings": [],
        "capability": None,
        "summary": None,
        "error": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    threading.Thread(target=_run_audit, args=(job_id, target), daemon=True).start()
    return {"job_id": job_id}


@app.websocket("/ws/audit/{job_id}")
async def audit_ws(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    job = jobs.get(job_id)
    if job is None:
        await websocket.send_json({"type": "error", "message": "unknown job_id"})
        await websocket.close()
        return

    q: queue.Queue = job["queue"]
    try:
        while True:
            event = await asyncio.to_thread(q.get)
            if event is None:  # end-of-stream sentinel
                break
            await websocket.send_json(event)
    except WebSocketDisconnect:
        return
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass


@app.get("/api/report/{job_id}")
def get_report(job_id: str) -> dict[str, Any]:
    job = jobs.get(job_id)
    if job is None:
        return {"error": "unknown job_id"}
    return {
        "target": job["target"].base_url,
        "timestamp": job["created_at"],
        "status": job["status"],
        "signing_capability": job["capability"] or "NOT ESTABLISHED",
        "summary": job["summary"],
        "findings": job["findings"],
    }


@app.post("/api/decode")
def decode(req: DecodeRequest) -> dict[str, Any]:
    """Decode a JWT's header + payload without verifying. Never raises."""
    token = (req.token or "").strip()
    parts = token.split(".")
    if len(parts) < 2:
        return {"header": None, "payload": None, "error": "Not a JWT (expected header.payload.signature)"}

    def _seg(segment: str) -> Any:
        padding = "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(segment + padding)
        return json.loads(raw.decode("utf-8"))

    try:
        header = _seg(parts[0])
        payload = _seg(parts[1])
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        return {"header": None, "payload": None, "error": f"Could not decode: {exc}"}
    return {"header": header, "payload": payload, "error": None}


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "probes": len(all_probes())}

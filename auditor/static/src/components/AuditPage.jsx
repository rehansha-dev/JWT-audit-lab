import { useRef } from "react";
import Navbar from "./Navbar.jsx";
import JwtDecoder from "./JwtDecoder.jsx";
import ProbeTable from "./ProbeTable.jsx";
import { Globe, User, Lock, Shield, Download, ArrowRight, LockBig } from "./icons.jsx";

const API = "http://localhost:8001";
const WS = "ws://localhost:8001";

const QUICK = [
  { label: "Vulnerable :4000", url: "http://localhost:4000", color: "var(--rose)" },
  { label: "Secure :4001", url: "http://localhost:4001", color: "var(--sage)" },
];

const FIELD_ICONS = {
  base_url: <Globe size={12} />,
  username: <User size={12} />,
  password: <Lock size={12} />,
  admin_path: <Shield size={12} />,
};

export default function AuditPage({ audit, onViewReport }) {
  const {
    findings, setFindings,
    capability, setCapability,
    summary, setSummary,
    jobId, setJobId,
    status, setStatus,
    error, setError,
    target, setTarget,
    setDuration, setScannedAt,
  } = audit;

  const cfg = useRef({ base_url: target || "http://localhost:4000", username: "alice", password: "password123", admin_path: "/admin" });
  const wsRef = useRef(null);
  const startTimeRef = useRef(null);

  const running = status === "running";
  const hasConfirmed = findings.some((f) => f.verdict === "CONFIRMED");

  const setField = (key) => (e) => {
    cfg.current[key] = e.target.value;
    if (key === "base_url") setTarget(e.target.value);
  };
  const setQuick = (url) => {
    cfg.current.base_url = url;
    setTarget(url);
  };

  // ----- WebSocket audit logic (behavior unchanged) -----
  const startAudit = async () => {
    if (wsRef.current) {
      try { wsRef.current.close(); } catch { /* ignore */ }
    }
    setFindings([]);
    setCapability(null);
    setSummary(null);
    setError(null);
    setStatus("running");
    setTarget(cfg.current.base_url);
    startTimeRef.current = Date.now();
    setScannedAt(new Date().toISOString());

    try {
      const res = await fetch(`${API}/api/audit/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(cfg.current),
      });
      const { job_id } = await res.json();
      setJobId(job_id);

      const ws = new WebSocket(`${WS}/ws/audit/${job_id}`);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        let msg;
        try { msg = JSON.parse(event.data); } catch { return; }
        if (msg.type === "probe_result") {
          setFindings((prev) => [...prev, msg]);
        } else if (msg.type === "capability") {
          setCapability(msg.signing_capability);
        } else if (msg.type === "complete") {
          setSummary(msg.summary);
          setStatus("complete");
          setDuration(startTimeRef.current ? Date.now() - startTimeRef.current : null);
          try { ws.close(); } catch { /* ignore */ }
        } else if (msg.type === "error") {
          setError(msg.message);
          setStatus("error");
          try { ws.close(); } catch { /* ignore */ }
        }
      };
      ws.onerror = () => {
        setError((p) => p || "WebSocket error — is the API running on :8001?");
        setStatus((s) => (s === "complete" ? s : "error"));
      };
    } catch (e) {
      setError(e.message || "Could not start audit");
      setStatus("error");
    }
  };

  const downloadReport = async () => {
    if (!jobId) return;
    try {
      const res = await fetch(`${API}/api/report/${jobId}`);
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "report.json";
      a.click();
      URL.revokeObjectURL(url);
    } catch { /* ignore */ }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-root)" }}>
      <Navbar alert={hasConfirmed} statusText={running ? "Scanning" : hasConfirmed ? "Threats Detected" : "System Ready"} />

      <div style={{ maxWidth: 1360, margin: "0 auto", padding: "78px 40px 60px" }}>
        <div style={{ display: "flex", gap: 32, alignItems: "flex-start", flexWrap: "wrap" }}>
          {/* LEFT */}
          <div style={{ width: 380, flexShrink: 0 }}>
            <div className="glass" style={{ padding: 32 }}>
              <EyebrowBar>Target Configuration</EyebrowBar>

              <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
                <Field name="base_url" label="Base URL" value={target} onChange={setField("base_url")} mono />
                <Field name="username" label="Username" defaultValue={cfg.current.username} onChange={setField("username")} />
                <Field name="password" label="Password" defaultValue={cfg.current.password} onChange={setField("password")} />
                <Field name="admin_path" label="Admin Path" defaultValue={cfg.current.admin_path} onChange={setField("admin_path")} mono />
              </div>

              <div className="eyebrow" style={{ margin: "24px 0 12px" }}>Quick Targets</div>
              <div style={{ display: "flex", gap: 8 }}>
                {QUICK.map((q) => (
                  <button key={q.url} className={`btn-quick ${target === q.url ? "active" : ""}`} onClick={() => setQuick(q.url)}>
                    <span className="dot" style={{ width: 5, height: 5, background: q.color }} />
                    {q.label}
                  </button>
                ))}
              </div>

              <div style={{ height: 1, margin: "24px 0", background: "linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.08) 50%, transparent 100%)" }} />

              <button className="btn-run" onClick={startAudit} disabled={running}>
                <span>{running ? "Scanning..." : "Run Audit"}</span>
              </button>

              <StatusLine status={status} count={findings.length} error={error} />
            </div>

            <JwtDecoder />
          </div>

          {/* RIGHT */}
          <div style={{ flex: 1, minWidth: 440 }}>
            {status === "idle" ? (
              <EmptyState />
            ) : (
              <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: 20 }}>
                <ResultsHeader running={running} complete={status === "complete"} />

                {status === "complete" && summary && <SummaryBanner summary={summary} />}
                {status === "error" && <ErrorBanner error={error} />}

                {findings.length > 0 && <ProbeTable findings={findings} capability={capability} />}

                {status === "complete" && jobId && (
                  <div style={{ display: "flex", gap: 12, marginTop: 4 }}>
                    <button className="btn btn-glass" style={{ padding: "10px 20px" }} onClick={downloadReport}>
                      <span style={{ color: "var(--text-3)", display: "inline-flex" }}><Download size={14} /></span>
                      Download Report
                    </button>
                    {summary?.confirmed > 0 && (
                      <button className="btn btn-grad" style={{ padding: "10px 24px", fontSize: 13 }} onClick={onViewReport}>
                        View Full Report <ArrowRight size={14} />
                      </button>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function EyebrowBar({ children }) {
  return (
    <div className="eyebrow" style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 24 }}>
      <span style={{ width: 3, height: 14, background: "var(--rose)", borderRadius: 2 }} />
      {children}
    </div>
  );
}

function Field({ name, label, value, defaultValue, onChange, mono }) {
  return (
    <div>
      <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 500, color: "var(--text-3)", marginBottom: 7 }}>
        <span style={{ color: "var(--text-4)", display: "inline-flex" }}>{FIELD_ICONS[name]}</span>
        {label}
      </label>
      <input className={`inp ${mono ? "mono" : ""}`} value={value} defaultValue={value === undefined ? defaultValue : undefined} onChange={onChange} />
    </div>
  );
}

function StatusLine({ status, count, error }) {
  if (status === "running")
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14, height: 20, fontSize: 12, color: "var(--amber)" }}>
        <span className="dot pulse-dot" style={{ width: 7, height: 7, background: "var(--amber)" }} />
        Scanning probe {Math.min(count + 1, 7)} of 7...
      </div>
    );
  if (status === "complete")
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14, height: 20, fontSize: 12, color: "var(--sage)" }}>
        <span className="dot" style={{ width: 7, height: 7, background: "var(--sage)" }} />✓ Audit complete
      </div>
    );
  if (status === "error")
    return <div style={{ marginTop: 14, fontSize: 12, color: "var(--rose)" }}>✗ {error}</div>;
  return <div style={{ marginTop: 14, height: 20 }} />;
}

function EmptyState() {
  const steps = ["Set target URL", "Click Run Audit", "Watch vulnerabilities appear live"];
  return (
    <div className="glass" style={{ minHeight: 500, height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 20, padding: 40 }}>
      <span style={{ color: "var(--text-4)" }}><LockBig size={64} /></span>
      <div className="font-sora" style={{ fontSize: 20, fontWeight: 600, color: "var(--text-4)" }}>Configure and run an audit</div>
      <div style={{ fontSize: 14, color: "var(--text-4)", maxWidth: 280, textAlign: "center" }}>
        Results will appear here in real-time as each probe completes
      </div>
      <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 10 }}>
        {steps.map((s, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ width: 20, height: 20, borderRadius: "50%", border: "1px solid var(--text-4)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, color: "var(--text-4)" }}>{i + 1}</span>
            <span style={{ fontSize: 13, color: "var(--text-4)" }}>{s}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ResultsHeader({ running, complete }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
      <h2 className="font-sora" style={{ fontSize: 20, fontWeight: 700, color: "var(--text-1)" }}>Live Probe Results</h2>
      {running && (
        <span style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "var(--amber)" }}>
          <span className="dot pulse-dot" style={{ width: 7, height: 7, background: "var(--amber)" }} />Scanning...
        </span>
      )}
      {complete && (
        <span style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "var(--sage)" }}>
          <span className="dot" style={{ width: 7, height: 7, background: "var(--sage)" }} />✓ Complete
        </span>
      )}
    </div>
  );
}

function SummaryBanner({ summary }) {
  const confirmed = summary.confirmed || 0;
  const exploit = confirmed > 0;
  const c = exploit ? "var(--rose)" : "var(--sage)";
  const bg = exploit
    ? "linear-gradient(135deg, rgba(242,168,168,0.07) 0%, rgba(242,168,168,0.03) 100%)"
    : "linear-gradient(135deg, rgba(147,212,168,0.07) 0%, rgba(147,212,168,0.03) 100%)";
  const border = exploit ? "var(--rose-border)" : "var(--sage-border)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14, borderRadius: 12, padding: "14px 20px", background: bg, border: `1px solid ${border}`, borderLeft: `3px solid ${c}` }}>
      <span style={{ width: 20, height: 20, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", background: exploit ? "var(--rose-bg-strong)" : "var(--sage-bg)", color: c, fontSize: 13 }}>
        {exploit ? "⚠" : "✓"}
      </span>
      <div>
        <div className="font-sora" style={{ fontSize: 14, fontWeight: 700, color: c }}>
          {exploit ? `${confirmed} vulnerabilit${confirmed === 1 ? "y" : "ies"} confirmed` : "No vulnerabilities confirmed"}
        </div>
        <div style={{ fontSize: 12, color: exploit ? "rgba(242,168,168,0.6)" : "rgba(147,212,168,0.6)" }}>
          {exploit ? "This server is exploitable" : "This server is hardened"}
        </div>
      </div>
    </div>
  );
}

function ErrorBanner({ error }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14, borderRadius: 12, padding: "14px 20px", background: "rgba(242,168,168,0.06)", border: "1px solid var(--rose-border)", borderLeft: "3px solid var(--rose)", color: "var(--rose)", fontSize: 14 }}>
      ✗ Audit failed: <span className="mono">{error}</span>
    </div>
  );
}

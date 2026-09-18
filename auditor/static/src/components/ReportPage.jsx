import { useState } from "react";
import Navbar from "./Navbar.jsx";
import { ArrowLeft, Key, Shield, Info, Chevron, Check, Bolt } from "./icons.jsx";

const OWASP_URL =
  "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html";

const gradNum = (from, to) => ({
  background: `linear-gradient(135deg, ${from} 0%, ${to} 100%)`,
  WebkitBackgroundClip: "text",
  backgroundClip: "text",
  WebkitTextFillColor: "transparent",
});

export default function ReportPage({ findings, summary, capability, target, duration, scannedAt, onBack }) {
  const confirmed = findings.filter((f) => f.verdict === "CONFIRMED");
  const rejected = findings.filter((f) => f.verdict !== "CONFIRMED");
  const critical = confirmed.filter((f) => f.severity === "CRITICAL").length;
  const high = confirmed.filter((f) => f.severity === "HIGH").length;
  const total = summary?.total ?? findings.length;

  const when = scannedAt ? new Date(scannedAt).toLocaleString() : "—";
  const dur = duration != null ? `~${Math.max(1, Math.round(duration / 1000))}s` : "—";
  const gained = capability && capability !== "NOT ESTABLISHED";
  const method = gained ? capability.replace(/^GAINED via /, "") : "";

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-root)" }}>
      <Navbar alert={confirmed.length > 0} statusText={confirmed.length > 0 ? "Threats Detected" : "System Ready"} />

      <div style={{ maxWidth: 920, margin: "0 auto", padding: "100px 40px 80px" }}>
        <button
          className="btn"
          style={{ background: "transparent", color: "var(--text-3)", fontSize: 13, fontWeight: 500, marginBottom: 48, padding: 0, gap: 8 }}
          onMouseEnter={(e) => { e.currentTarget.style.color = "var(--text-1)"; e.currentTarget.style.transform = "translateX(-2px)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.color = "var(--text-3)"; e.currentTarget.style.transform = "none"; }}
          onClick={onBack}
        >
          <ArrowLeft size={14} /> Back to Audit
        </button>

        {/* Header */}
        <div className="fade-up">
          <div className="eyebrow" style={{ letterSpacing: 3, marginBottom: 16 }}>Security Audit Report</div>
          <h1 className="font-sora" style={{ fontSize: 52, fontWeight: 800, lineHeight: 1, letterSpacing: "-2px", color: "var(--text-1)", marginBottom: 24 }}>
            Security Report
          </h1>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 24 }}>
            <Meta label="Target" value={target} mono valueColor="var(--sky)" />
            <Meta label="Scanned At" value={when} />
            <Meta label="Duration" value={dur} />
          </div>
        </div>

        <div style={{ height: 1, margin: "40px 0", background: "linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.1) 20%, rgba(255,255,255,0.1) 80%, transparent 100%)" }} />

        {/* Stat cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 48 }}>
          <StatCard value={critical} label="Critical" numStyle={gradNum("var(--rose)", "var(--rose-dim)")} delay="0.05s" />
          <StatCard value={high} label="High" numStyle={gradNum("var(--amber)", "var(--amber-dim)")} delay="0.1s" />
          <StatCard value={total} label="Probes Run" numStyle={{ color: "var(--text-1)" }} delay="0.15s" />
        </div>

        {/* Signing capability bar */}
        <div
          className="glass"
          style={{
            padding: "18px 24px",
            display: "flex",
            alignItems: "center",
            gap: 14,
            marginBottom: 40,
            background: gained ? "linear-gradient(135deg, rgba(240,202,140,0.08) 0%, rgba(240,202,140,0.04) 100%)" : undefined,
            borderColor: gained ? "var(--amber-border)" : undefined,
          }}
        >
          <span style={{ width: 36, height: 36, borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "center", background: gained ? "var(--amber-bg)" : "rgba(255,255,255,0.04)", border: `1px solid ${gained ? "var(--amber-border)" : "var(--glass-border)"}`, color: gained ? "var(--amber)" : "var(--text-4)" }}>
            {gained ? <Bolt size={18} /> : <span style={{ fontSize: 16 }}>○</span>}
          </span>
          <div>
            <div className="font-sora" style={{ fontSize: 14, fontWeight: 700, color: gained ? "var(--amber)" : "var(--text-3)" }}>
              {gained ? "Signing Capability Gained" : "Signing Capability Not Established"}
            </div>
            <div style={{ fontSize: 12, color: gained ? "rgba(240,202,140,0.6)" : "var(--text-4)" }}>
              {gained ? `via ${method} bypass — Phase B probes executed` : "No forgery primitive succeeded — Phase B skipped"}
            </div>
          </div>
        </div>

        {/* Confirmed vulnerabilities */}
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 24 }}>
          <h2 className="font-sora" style={{ fontSize: 22, fontWeight: 700, color: "var(--text-1)" }}>Confirmed Vulnerabilities</h2>
          <span className="font-sora" style={{ fontSize: 14, fontWeight: 700, color: "var(--rose)", background: "var(--rose-bg-strong)", border: "1px solid var(--rose-border)", padding: "3px 12px", borderRadius: "var(--r-full)" }}>
            {confirmed.length}
          </span>
        </div>

        {confirmed.length === 0 ? (
          <div className="glass" style={{ padding: 28, color: "var(--text-3)", fontSize: 14 }}>
            No vulnerabilities confirmed — every attack was correctly rejected.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {confirmed.map((f, i) => (
              <FindingCard key={i} f={f} delay={`${i * 0.06}s`} />
            ))}
          </div>
        )}

        {rejected.length > 0 && <RejectedSection findings={rejected} />}
      </div>
    </div>
  );
}

function Meta({ label, value, mono, valueColor }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      <span className="eyebrow">{label}</span>
      <span className={mono ? "mono" : ""} style={{ fontSize: 14, color: valueColor || "var(--text-2)", wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

function StatCard({ value, label, numStyle, delay }) {
  return (
    <div className="glass fade-up" style={{ padding: "28px 32px", textAlign: "center", animationDelay: delay }}>
      <div className="font-sora" style={{ fontSize: 64, fontWeight: 800, lineHeight: 1, letterSpacing: "-3px", marginBottom: 8, ...numStyle }}>{value}</div>
      <div className="eyebrow">{label}</div>
    </div>
  );
}

function SevBadge({ severity }) {
  const crit = severity === "CRITICAL";
  return (
    <span style={{ background: crit ? "var(--rose-bg-strong)" : "var(--amber-bg)", color: crit ? "var(--rose)" : "var(--amber)", border: `1px solid ${crit ? "var(--rose-border)" : "var(--amber-border)"}`, fontFamily: "Inter", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, padding: "3px 10px", borderRadius: 6 }}>
      {severity}
    </span>
  );
}

function FindingCard({ f, delay }) {
  const [open, setOpen] = useState(false);
  const ev = f.evidence || {};
  return (
    <div className="glass fade-up" style={{ borderLeft: "3px solid var(--rose)", padding: 0, animationDelay: delay }}>
      {/* header */}
      <div style={{ padding: "24px 28px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <span className="font-sora" style={{ fontSize: 17, fontWeight: 700, color: "var(--text-1)" }}>{f.title}</span>
          {f.cve && <span className="cve-pill">{f.cve}</span>}
          <SevBadge severity={f.severity} />
          <span className="cwe-pill">{f.cwe}</span>
        </div>
        <p style={{ marginTop: 10, fontSize: 14, fontWeight: 300, lineHeight: 1.7, color: "var(--text-3)", fontStyle: "italic" }}>{f.summary}</p>
      </div>

      {/* footer toggle */}
      <div style={{ padding: "16px 28px", background: "rgba(255,255,255,0.015)", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
        <button className="btn" style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: "var(--r-sm)", padding: "8px 16px", fontSize: 12, fontWeight: 500, color: "var(--text-3)" }}
          onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.07)"; e.currentTarget.style.color = "var(--text-1)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; e.currentTarget.style.color = "var(--text-3)"; }}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? "Hide Evidence" : "Show Evidence"}
          <span style={{ display: "inline-flex", transform: open ? "rotate(180deg)" : "none", transition: "transform var(--t-base) var(--ease)" }}><Chevron size={13} /></span>
        </button>
      </div>

      {/* evidence */}
      <div style={{ maxHeight: open ? 900 : 0, overflow: "hidden", transition: "max-height 0.4s var(--ease)" }}>
        {open && (
          <div style={{ padding: "20px 28px 24px", borderTop: "1px solid rgba(255,255,255,0.05)", display: "flex", flexDirection: "column", gap: 16 }}>
            <Block icon={<Key size={12} />} iconColor="var(--rose)" label="Forged Token">
              <div className="evi-box" style={{ color: "var(--amber)" }}>
                <Copy text={ev.forged_token || ""} />
                {ev.forged_token || "—"}
              </div>
            </Block>
            <Block icon={<Shield size={12} />} iconColor="var(--sage)" label="Server Response"
              extra={<span style={{ background: "var(--sage-bg)", color: "var(--sage)", border: "1px solid var(--sage-border)", fontFamily: "JetBrains Mono", fontSize: 10, padding: "2px 8px", borderRadius: 5 }}>{ev.http_status} OK</span>}
            >
              <div className="evi-box" style={{ color: "var(--sage)", background: "rgba(147,212,168,0.03)", borderColor: "rgba(147,212,168,0.15)", padding: "14px 16px" }}>{ev.response}</div>
            </Block>
            <Block icon={<Info size={12} />} iconColor="var(--sky)" label="Remediation">
              <div style={{ background: "rgba(147,212,168,0.04)", border: "1px solid rgba(147,212,168,0.15)", borderRadius: 10, padding: "16px 20px" }}>
                <div style={{ fontSize: 13, lineHeight: 1.75, color: "rgba(147,212,168,0.85)" }}>{f.remediation}</div>
                <a href={OWASP_URL} target="_blank" rel="noreferrer" style={{ display: "inline-block", marginTop: 10, fontSize: 12, fontWeight: 500, color: "var(--sky)" }}>↗ OWASP JWT Cheat Sheet</a>
              </div>
            </Block>
          </div>
        )}
      </div>
    </div>
  );
}

function Block({ icon, iconColor, label, extra, children }) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <span style={{ color: iconColor, display: "inline-flex" }}>{icon}</span>
        <span className="eyebrow">{label}</span>
        {extra}
      </div>
      {children}
    </div>
  );
}

function RejectedSection({ findings }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ marginTop: 48 }}>
      <div onClick={() => setOpen((o) => !o)} style={{ display: "flex", alignItems: "center", gap: 12, cursor: "pointer", marginBottom: 16 }}>
        <span style={{ display: "inline-flex", color: "var(--text-3)", transform: open ? "rotate(180deg)" : "none", transition: "transform var(--t-base) var(--ease)" }}><Chevron size={14} /></span>
        <span className="font-sora" style={{ fontSize: 18, fontWeight: 600, color: "var(--text-3)" }}>Correctly Rejected Attacks</span>
        <span style={{ fontFamily: "Sora", fontSize: 13, fontWeight: 700, color: "var(--text-4)", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", padding: "2px 10px", borderRadius: "var(--r-full)" }}>{findings.length}</span>
      </div>

      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {findings.map((f, i) => (
            <div key={i} className="glass" style={{ display: "flex", alignItems: "center", gap: 16, padding: "16px 20px", borderRadius: 12 }}>
              <span style={{ width: 32, height: 32, borderRadius: 8, flexShrink: 0, background: f.verdict === "SKIPPED" ? "rgba(255,255,255,0.04)" : "var(--sage-bg)", border: `1px solid ${f.verdict === "SKIPPED" ? "var(--glass-border)" : "var(--sage-border)"}`, display: "flex", alignItems: "center", justifyContent: "center", color: f.verdict === "SKIPPED" ? "var(--text-4)" : "var(--sage)" }}>
                {f.verdict === "SKIPPED" ? "○" : <Check size={14} />}
              </span>
              <div style={{ minWidth: 0 }}>
                <span className="mono" style={{ fontSize: 14, fontWeight: 600, color: "var(--text-2)" }}>{f.probe}</span>
                <span style={{ fontSize: 13, color: "var(--text-4)" }}> — {f.summary}</span>
              </div>
              {f.cve && <span className="cve-pill" style={{ marginLeft: "auto", flexShrink: 0 }}>{f.cve}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Copy({ text }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard blocked */
    }
  };
  return (
    <button className="copy-btn" style={copied ? { color: "var(--sage)" } : undefined} onClick={onCopy}>
      {copied ? "Copied ✓" : "Copy"}
    </button>
  );
}

import { useState } from "react";
import { Key, Shield, Info, Caret, Bolt } from "./icons.jsx";

const OWASP_URL =
  "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html";

const PHASE_B = new Set(["expiration"]); // capability line renders before these

const COL = { probe: 220, verdict: 130, sev: 90, cwe: 90 };
const ACCENT = { CONFIRMED: "var(--rose)", NOT_VULNERABLE: "var(--sage)", SKIPPED: "var(--text-4)" };

export default function ProbeTable({ findings, capability }) {
  let capInserted = false;
  const rows = [];
  findings.forEach((f, i) => {
    if (PHASE_B.has(f.probe) && !capInserted && capability != null) {
      rows.push(<CapabilityRow key="cap" capability={capability} />);
      capInserted = true;
    }
    rows.push(<Row key={`${f.probe}-${i}`} f={f} index={i} />);
  });

  return (
    <div className="glass" style={{ overflow: "hidden" }}>
      {/* header */}
      <div style={{ height: 44, padding: "0 20px 0 24px", display: "flex", alignItems: "center", background: "rgba(255,255,255,0.02)", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
        <HeaderCell w={COL.probe}>Probe</HeaderCell>
        <HeaderCell w={COL.verdict}>Verdict</HeaderCell>
        <HeaderCell w={COL.sev}>Sev</HeaderCell>
        <HeaderCell w={COL.cwe}>CWE</HeaderCell>
        <HeaderCell flex>Finding</HeaderCell>
      </div>
      {rows}
    </div>
  );
}

function HeaderCell({ children, w, flex }) {
  return (
    <div style={{ width: w, flex: flex ? 1 : undefined, fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: 1.5, color: "var(--text-4)", fontFamily: "Inter" }}>
      {children}
    </div>
  );
}

function Row({ f, index }) {
  const [open, setOpen] = useState(false);
  const expandable = f.verdict === "CONFIRMED";
  const accent = ACCENT[f.verdict] || "var(--text-4)";
  const skipped = f.verdict === "SKIPPED";
  const baseBg = f.verdict === "CONFIRMED" ? "rgba(242,168,168,0.02)" : "transparent";

  return (
    <div className="row-in" style={{ position: "relative", borderBottom: "1px solid rgba(255,255,255,0.04)", animationDelay: `${Math.min(index * 60, 480)}ms`, opacity: skipped ? 0.6 : 1 }}>
      {/* accent bar */}
      <span style={{ position: "absolute", left: 0, top: 0, width: 3, height: "100%", background: accent }} />

      <div
        onClick={() => expandable && setOpen((o) => !o)}
        onMouseEnter={(e) => (e.currentTarget.style.background = expandable ? "rgba(242,168,168,0.04)" : skipped ? baseBg : "rgba(255,255,255,0.015)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = baseBg)}
        style={{
          display: "flex",
          alignItems: "center",
          height: 56,
          padding: "0 20px 0 24px",
          background: baseBg,
          cursor: expandable ? "pointer" : "default",
          transition: "background var(--t-fast) var(--ease)",
        }}
      >
        {/* PROBE */}
        <div style={{ width: COL.probe, display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <span style={{ color: expandable ? "var(--rose)" : "var(--text-4)", display: "inline-flex", transform: open ? "rotate(90deg)" : "none", transition: "transform var(--t-base) var(--ease)" }}>
            <Caret size={9} />
          </span>
          <span className="mono" style={{ fontSize: 13, fontWeight: 500, color: "var(--text-1)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.probe}</span>
        </div>
        {/* VERDICT */}
        <div style={{ width: COL.verdict }}><Verdict verdict={f.verdict} /></div>
        {/* SEV */}
        <div style={{ width: COL.sev }}><Sev severity={f.severity} muted={skipped || f.verdict === "NOT_VULNERABLE"} /></div>
        {/* CWE */}
        <div style={{ width: COL.cwe }}><span className="cwe-pill">{f.cwe}</span></div>
        {/* FINDING */}
        <div style={{ flex: 1, fontSize: 13, color: "var(--text-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={f.summary}>{f.summary || f.title}</div>
      </div>

      {/* Expanded detail (max-height animation) */}
      {expandable && (
        <div style={{ maxHeight: open ? 700 : 0, overflow: "hidden", transition: "max-height 0.4s var(--ease)", background: "rgba(242,168,168,0.025)" }}>
          {open && <Detail f={f} />}
        </div>
      )}
    </div>
  );
}

function Verdict({ verdict }) {
  if (verdict === "CONFIRMED")
    return <span className="pill pill-confirmed"><span className="dot" style={{ width: 4, height: 4, background: "var(--rose)" }} />Confirmed</span>;
  if (verdict === "NOT_VULNERABLE")
    return <span className="pill pill-safe"><span className="dot" style={{ width: 4, height: 4, background: "var(--sage)" }} />Safe</span>;
  if (verdict === "SKIPPED") return <span className="pill pill-skipped">Skipped</span>;
  return <span className="pill pill-skipped">{verdict}</span>;
}

function Sev({ severity, muted }) {
  const color = muted ? "var(--text-4)" : severity === "CRITICAL" ? "var(--rose)" : severity === "HIGH" ? "var(--amber)" : "var(--sky)";
  return <span className="sev-badge" style={{ color }}>{severity}</span>;
}

function Detail({ f }) {
  const ev = f.evidence || {};
  return (
    <div style={{ padding: "20px 20px 24px 24px", display: "flex", flexDirection: "column", gap: 16 }}>
      {f.cve && <div><span className="cve-pill">{f.cve}</span></div>}

      <Block icon={<Key size={12} />} iconColor="var(--rose)" label="Forged Token">
        <div className="evi-box" style={{ color: "var(--amber)" }}>
          <Copy text={ev.forged_token || ""} />
          {ev.forged_token || "—"}
        </div>
      </Block>

      <Block
        icon={<Shield size={12} />}
        iconColor="var(--sage)"
        label="Server Response"
        extra={<span style={{ background: "var(--sage-bg)", color: "var(--sage)", border: "1px solid var(--sage-border)", fontFamily: "JetBrains Mono", fontSize: 10, padding: "2px 8px", borderRadius: 5 }}>{ev.http_status} OK</span>}
      >
        <div className="evi-box" style={{ color: "var(--sage)", background: "rgba(147,212,168,0.03)", borderColor: "rgba(147,212,168,0.15)", padding: "14px 16px" }}>
          {ev.response}
        </div>
      </Block>

      <Block icon={<Info size={12} />} iconColor="var(--sky)" label="Remediation">
        <div style={{ background: "rgba(147,212,168,0.04)", border: "1px solid rgba(147,212,168,0.15)", borderRadius: 10, padding: "16px 20px" }}>
          <div style={{ fontSize: 13, lineHeight: 1.75, color: "rgba(147,212,168,0.85)" }}>{f.remediation}</div>
          <a href={OWASP_URL} target="_blank" rel="noreferrer" style={{ display: "inline-block", marginTop: 10, fontSize: 12, fontWeight: 500, color: "var(--sky)" }}>
            ↗ OWASP JWT Cheat Sheet
          </a>
        </div>
      </Block>
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

function CapabilityRow({ capability }) {
  const gained = capability && capability !== "NOT ESTABLISHED";
  return (
    <div style={{ height: 42, padding: "0 20px 0 24px", display: "flex", alignItems: "center", gap: 10, background: "rgba(240,202,140,0.04)", borderTop: "1px solid rgba(240,202,140,0.1)", borderBottom: "1px solid rgba(240,202,140,0.1)" }}>
      {gained ? (
        <span style={{ color: "var(--amber)", display: "inline-flex" }}><Bolt size={14} /></span>
      ) : (
        <span style={{ color: "var(--text-4)" }}>○</span>
      )}
      <span style={{ fontSize: 12, fontWeight: gained ? 500 : 400, color: gained ? "var(--amber)" : "var(--text-4)" }}>
        {gained ? `Signing capability ${capability}` : "Signing capability NOT ESTABLISHED — Phase B skipped"}
      </span>
    </div>
  );
}

function Copy({ text }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async (e) => {
    e.stopPropagation();
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

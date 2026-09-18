import { Shield } from "./icons.jsx";

export default function Navbar({ alert = false, statusText = "System Ready" }) {
  return (
    <nav
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        zIndex: 200,
        height: 58,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 48px",
        background: "rgba(8,8,16,0.8)",
        backdropFilter: "blur(24px) saturate(200%)",
        WebkitBackdropFilter: "blur(24px) saturate(200%)",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        boxShadow: "0 1px 0 rgba(255,255,255,0.03)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            background: "var(--rose-bg-strong)",
            border: "1px solid var(--rose-border)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--rose)",
          }}
        >
          <Shield size={16} />
        </div>
        <span className="font-sora" style={{ fontSize: 15, fontWeight: 700, color: "var(--text-1)", letterSpacing: "-0.3px" }}>
          JWT Audit Lab
        </span>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span
            className={alert ? "dot glow-pulse" : "dot"}
            style={{ background: alert ? "var(--rose)" : "var(--text-4)" }}
          />
          <span style={{ fontSize: 12, color: "var(--text-3)" }}>{statusText}</span>
        </div>
        <span style={{ width: 1, height: 20, background: "var(--glass-border)" }} />
        <span
          style={{
            fontSize: 10,
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: 1.5,
            color: "var(--rose)",
            background: "var(--rose-bg)",
            border: "1px solid var(--rose-border)",
            padding: "5px 14px",
            borderRadius: "var(--r-full)",
          }}
        >
          Authorized Use Only
        </span>
      </div>
    </nav>
  );
}

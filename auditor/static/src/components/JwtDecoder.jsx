import { useEffect, useState } from "react";

const API = "http://localhost:8001";

export default function JwtDecoder() {
  const [token, setToken] = useState("");
  const [decoded, setDecoded] = useState(null); // {header, payload, error}

  // Real-time decode (debounced). Network/state logic unchanged.
  useEffect(() => {
    const trimmed = token.trim();
    if (!trimmed) {
      setDecoded(null);
      return;
    }
    const id = setTimeout(async () => {
      try {
        const res = await fetch(`${API}/api/decode`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: trimmed }),
        });
        setDecoded(await res.json());
      } catch {
        setDecoded({ header: null, payload: null, error: "Backend unreachable" });
      }
    }, 150);
    return () => clearTimeout(id);
  }, [token]);

  return (
    <div className="glass" style={{ padding: 28, marginTop: 20 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
        <span className="eyebrow">JWT Decoder</span>
        <span
          style={{
            fontSize: 9,
            textTransform: "uppercase",
            letterSpacing: 1,
            color: "var(--sage)",
            background: "var(--sage-bg)",
            border: "1px solid var(--sage-border)",
            padding: "3px 8px",
            borderRadius: "var(--r-full)",
          }}
        >
          Real-Time
        </span>
      </div>

      <textarea
        className="inp"
        placeholder="Paste any JWT token here..."
        spellCheck={false}
        value={token}
        onChange={(e) => setToken(e.target.value)}
      />

      {decoded?.error && <p style={{ color: "var(--rose)", fontSize: 12, marginTop: 10 }}>{decoded.error}</p>}

      {decoded && !decoded.error && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 14 }}>
          <Panel title="Header" data={decoded.header} />
          <Panel title="Payload" data={decoded.payload} />
        </div>
      )}
    </div>
  );
}

function Panel({ title, data }) {
  return (
    <div>
      <div className="eyebrow" style={{ fontSize: 9, marginBottom: 8 }}>{title}</div>
      <div
        style={{
          minHeight: 72,
          background: "rgba(255,255,255,0.025)",
          border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 8,
          padding: 12,
          overflowX: "auto",
        }}
      >
        <pre className="mono" style={{ fontSize: 11, lineHeight: 1.6, margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
          {renderNode(data, 0)}
        </pre>
      </div>
    </div>
  );
}

function isDangerValue(key, val) {
  if (typeof val !== "string") return false;
  if (key === "alg" && ["none", "None", "NONE"].includes(val)) return true;
  if (key === "role" && val === "admin") return true;
  return false;
}
function isJwkKey(key) {
  return typeof key === "string" && key.toLowerCase().includes("jwk");
}

function renderNode(node, indent, key = null) {
  const pad = "  ".repeat(indent);
  const childPad = "  ".repeat(indent + 1);

  if (node === null) return <span className="tok-null">null</span>;
  if (typeof node === "boolean") return <span className="tok-bool">{String(node)}</span>;
  if (typeof node === "number") return <span className="tok-number">{String(node)}</span>;
  if (typeof node === "string") {
    return <span className={isDangerValue(key, node) ? "tok-danger" : "tok-string"}>&quot;{node}&quot;</span>;
  }

  if (Array.isArray(node)) {
    if (node.length === 0) return <span>[]</span>;
    return (
      <>
        {"[\n"}
        {node.map((item, i) => (
          <span key={i}>
            {childPad}
            {renderNode(item, indent + 1)}
            {i < node.length - 1 ? "," : ""}
            {"\n"}
          </span>
        ))}
        {pad + "]"}
      </>
    );
  }

  const entries = Object.entries(node || {});
  if (entries.length === 0) return <span>{"{}"}</span>;
  return (
    <>
      {"{\n"}
      {entries.map(([k, v], i) => (
        <span key={k}>
          {childPad}
          <span className={isJwkKey(k) ? "tok-jwk" : "tok-key"}>&quot;{k}&quot;</span>
          {": "}
          {renderNode(v, indent + 1, k)}
          {i < entries.length - 1 ? "," : ""}
          {"\n"}
        </span>
      ))}
      {pad + "}"}
    </>
  );
}

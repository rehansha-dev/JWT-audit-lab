import { useState } from "react";
import LandingPage from "./components/LandingPage.jsx";
import AuditPage from "./components/AuditPage.jsx";
import ReportPage from "./components/ReportPage.jsx";

export default function App() {
  const [view, setView] = useState("landing"); // 'landing' | 'audit' | 'report'

  // Shared audit state (lifted so ReportPage can read the finished results).
  const [findings, setFindings] = useState([]);
  const [capability, setCapability] = useState(null);
  const [summary, setSummary] = useState(null);
  const [jobId, setJobId] = useState(null);
  const [status, setStatus] = useState("idle"); // idle | running | complete | error
  const [error, setError] = useState(null);
  const [target, setTarget] = useState("http://localhost:4000");
  const [duration, setDuration] = useState(null); // ms, client-measured for the report
  const [scannedAt, setScannedAt] = useState(null);

  const audit = {
    findings,
    setFindings,
    capability,
    setCapability,
    summary,
    setSummary,
    jobId,
    setJobId,
    status,
    setStatus,
    error,
    setError,
    target,
    setTarget,
    duration,
    setDuration,
    scannedAt,
    setScannedAt,
  };

  if (view === "landing") {
    return <LandingPage onStart={() => setView("audit")} />;
  }
  if (view === "report") {
    return (
      <ReportPage
        findings={findings}
        summary={summary}
        capability={capability}
        target={target}
        duration={duration}
        scannedAt={scannedAt}
        onBack={() => setView("audit")}
      />
    );
  }
  return <AuditPage audit={audit} onViewReport={() => setView("report")} />;
}

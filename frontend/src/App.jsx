// src/App.jsx — BREACH PROTOCOL UI
import { useState, useRef } from "react";
import "./breach.css";

import ParticleField from "./components/ui/ParticleField";
import ThreeScene from "./components/ui/ThreeScene";
import HeroInput from "./components/ui/HeroInput";
import ScanTerminal from "./components/ui/ScanTerminal";
import ScanCompleteBanner from "./components/ui/ScanCompleteBanner";

import HeaderScanner from "./components/modules/HeaderScanner";
import PortScanner from "./components/modules/PortScanner";
import DirectoryScanner from "./components/modules/DirectoryScanner";
import GitHubScanner from "./components/modules/GitHubScanner";
import BusinessLogicScanner from "./components/modules/BusinessLogicScanner";
import CloudScanner from "./components/modules/CloudScanner";
import RiskDashboard from "./components/modules/RiskDashboard";

const API = "http://127.0.0.1:5000";

const MODULES = [
  { key: "header", endpoint: "/scan/header", label: "HEADER ANALYSIS", canRun: ({ url }) => !!url, body: ({ url, sid }) => ({ url, scan_id: sid }) },
  { key: "tls", endpoint: "/scan/tls", label: "TLS INSPECTION", canRun: ({ url }) => !!url, body: ({ url, sid }) => ({ url, scan_id: sid }) },
  { key: "ports", endpoint: "/scan/ports", label: "PORT RECON", canRun: ({ url }) => !!url, body: ({ url, sid }) => ({ url, scan_id: sid }) },
  { key: "directories", endpoint: "/scan/directories", label: "DIRECTORY ENUM", canRun: ({ url }) => !!url, body: ({ url, sid }) => ({ url, scan_id: sid }) },
  { key: "business", endpoint: "/scan/business", label: "BUSINESS LOGIC", canRun: ({ url }) => !!url, body: ({ url, jwt, sid }) => ({ url, scan_id: sid, jwt_token: jwt }) },
  { key: "cloud", endpoint: "/scan/cloud", label: "CLOUD MISCONFIG", canRun: ({ url }) => !!url, body: ({ url, sid }) => ({ url, scan_id: sid }) },
  { key: "github", endpoint: "/scan/github", label: "GITHUB SECRETS", canRun: ({ repoUrl }) => !!repoUrl, body: ({ repoUrl, sid }) => ({ repo_url: repoUrl, scan_id: sid }) },
];

const LOG_LINES = {
  header: ["Fetching HTTP response headers...", "Analysing Content-Security-Policy...", "Testing HSTS configuration...", "Checking X-Frame-Options...", "Querying Mozilla Observatory..."],
  tls: ["Resolving target hostname...", "Initiating TLS handshake...", "Extracting certificate details...", "Checking HSTS preload list...", "Grading cipher suite strength..."],
  ports: ["Running Nmap service scan...", "Probing common attack-surface ports...", "Fingerprinting detected services...", "Querying NVD for CVEs..."],
  directories: ["Establishing baseline response...", "Fuzzing 80+ sensitive paths...", "Validating content signatures...", "Checking for .git exposure...", "Testing GraphQL introspection..."],
  business: ["Testing CORS origin reflection...", "Probing null origin bypass...", "Analysing JWT algorithm...", "Attempting alg:none bypass...", "Scanning GraphQL schema..."],
  cloud: ["Enumerating S3 bucket candidates...", "Querying crt.sh for subdomains...", "Checking CNAME fingerprints...", "Probing Docker API...", "Testing Kubernetes dashboard..."],
  github: ["Resolving repository metadata...", "Enumerating repository tree...", "Scanning commits for leaked secrets...", "Checking sensitive file patterns...", "Scoring repository exposure..."],
  risk: ["Aggregating all findings...", "Calculating CVSS v3.1 scores...", "Running chain detection rules...", "Querying threat intelligence...", "Generating security grade..."],
};

const MODULE_TABS = [
  { key: "risk", label: "RISK", color: "#ff6600" },
  { key: "header", label: "HEADERS", color: "#00ff41" },
  { key: "tls", label: "TLS", color: "#0080ff" },
  { key: "ports", label: "PORTS", color: "#ff0040" },
  { key: "directories", label: "DIRS", color: "#ffaa00" },
  { key: "business", label: "LOGIC", color: "#aa00ff" },
  { key: "cloud", label: "CLOUD", color: "#00aaff" },
  { key: "github", label: "GITHUB", color: "#8b5cf6" },
];

function gradeColor(g) {
  return g === "A+" || g === "A" ? "#00ff41" : g === "B" ? "#0080ff" : g === "C" ? "#ffaa00" : g === "D" ? "#ff6600" : "#ff0040";
}

function normalizeTargetUrl(url) {
  const trimmed = url.trim();
  if (!trimmed) return "";
  return trimmed.startsWith("http://") || trimmed.startsWith("https://")
    ? trimmed
    : `https://${trimmed}`;
}

function normalizeRepoUrl(repoUrl) {
  const trimmed = repoUrl.trim();
  if (!trimmed) return "";
  return trimmed.startsWith("http://") || trimmed.startsWith("https://")
    ? trimmed
    : `https://github.com/${trimmed.replace(/^github\.com\//, "")}`;
}

export default function App() {
  const [phase, setPhase] = useState("landing");
  const [scanMode, setScanMode] = useState("full");
  const [target, setTarget] = useState("");
  const [repoTarget, setRepoTarget] = useState("");
  const [jwtToken, setJwtToken] = useState("");
  const [scanId, setScanId] = useState(null);
  const [results, setResults] = useState({});
  const [moduleStatuses, setModuleStatuses] = useState({});
  const [moduleProgress, setModuleProgress] = useState({});
  const [moduleFindings, setModuleFindings] = useState({});
  const [liveLog, setLiveLog] = useState([]);
  const [riskData, setRiskData] = useState(null);
  const [error, setError] = useState(null);
  const [activeModule, setActiveModule] = useState(null);
  const logIdx = useRef({});

  const addLog = (line) => setLiveLog(prev => [...prev.slice(-30), line]);

  const extractFindings = (key, data) => {
    try {
      if (key === "header") return data.findings || [];
      if (key === "tls") return (data.issues || []).map(i => ({ severity: "Medium", type: i }));
      if (key === "ports") return data.open_ports || [];
      if (key === "directories") return data.findings || [];
      if (key === "business") {
        const all = [];
        ["cors", "jwt", "graphql"].forEach(s => (data[s]?.findings || []).forEach(f => all.push(f)));
        return all;
      }
      if (key === "cloud") {
        const all = [];
        (data.s3?.findings || []).forEach(f => all.push(f));
        (data.subdomains?.takeover_findings || []).forEach(f => all.push(f));
        (data.services?.findings || []).forEach(f => all.push(f));
        return all;
      }
      if (key === "github") return data.secrets || [];
    } catch { return []; }
    return [];
  };

  const runProgressTicks = (key) => {
    let tick = 0; logIdx.current[key] = 0;
    const lines = LOG_LINES[key] || [];
    const id = setInterval(() => {
      tick++;
      setModuleProgress(p => ({ ...p, [key]: Math.min(88, tick * 12) }));
      const li = logIdx.current[key];
      if (li < lines.length) { addLog(lines[li]); logIdx.current[key]++; }
    }, 600);
    return id;
  };

  const scanModule = async (mod, sid, context) => {
    if (!mod.canRun(context)) {
      setModuleStatuses(p => ({ ...p, [mod.key]: "done" }));
      setModuleProgress(p => ({ ...p, [mod.key]: 100 }));
      setModuleFindings(p => ({ ...p, [mod.key]: [] }));
      addLog(`[${mod.label}] Skipped (missing required target)`);
      return null;
    }

    setModuleStatuses(p => ({ ...p, [mod.key]: "scanning" }));
    setModuleProgress(p => ({ ...p, [mod.key]: 5 }));
    addLog(`[${mod.label}] Initiating...`);
    const ticker = runProgressTicks(mod.key);
    try {
      const res = await fetch(`${API}${mod.endpoint}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(mod.body({ ...context, sid, jwt: jwtToken })) });
      const data = await res.json();
      clearInterval(ticker);
      setModuleProgress(p => ({ ...p, [mod.key]: 100 }));
      setModuleStatuses(p => ({ ...p, [mod.key]: "done" }));
      setResults(p => ({ ...p, [mod.key]: data }));
      const findings = extractFindings(mod.key, data);
      setModuleFindings(p => ({ ...p, [mod.key]: findings }));
      const crit = findings.filter(f => f.severity === "Critical").length;
      addLog(`[${mod.label}] Done — ${findings.length} findings${crit ? `, ${crit} critical` : ""}`);
      return data;
    } catch (err) {
      clearInterval(ticker);
      setModuleProgress(p => ({ ...p, [mod.key]: 100 }));
      setModuleStatuses(p => ({ ...p, [mod.key]: "done" }));
      addLog(`[${mod.label}] Error: ${err.message}`);
      return null;
    }
  };

  const startScan = async ({ url, repoUrl, repoOnly = false }) => {
    const normalizedUrl = normalizeTargetUrl(url || "");
    const normalizedRepoUrl = normalizeRepoUrl(repoUrl || "");
    setTarget(normalizedUrl); setPhase("scanning"); setError(null);
    setScanMode(repoOnly ? "repo" : "full");
    setRepoTarget(normalizedRepoUrl);
    setResults({}); setRiskData(null); setLiveLog([]);
    setModuleStatuses({}); setModuleProgress({}); setModuleFindings({});
    setActiveModule(repoOnly ? "github" : null);
    const initSt = {};
    MODULES.forEach(m => { initSt[m.key] = repoOnly && m.key !== "github" ? "done" : "waiting"; });
    initSt.risk = repoOnly ? "done" : "waiting";
    setModuleStatuses(initSt);

    addLog("BREACH PROTOCOL INITIATED");
    if (repoOnly) addLog("Mode: REPOSITORY-ONLY SCAN");
    if (normalizedUrl) addLog(`Web Target: ${normalizedUrl}`);
    if (normalizedRepoUrl) addLog(`GitHub Repo: ${normalizedRepoUrl}`);

    let sid = null;
    try {
      const ir = await fetch(`${API}/scan/init`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: normalizedUrl || normalizedRepoUrl }) });
      const ij = await ir.json(); sid = ij.scan_id; setScanId(sid);
      addLog(`Session: ${sid}`);
    } catch { addLog("Session init skipped"); }

    addLog("─".repeat(36));

    const context = { url: normalizedUrl, repoUrl: normalizedRepoUrl };
    const allData = {};
    for (const mod of MODULES) {
      if (repoOnly && mod.key !== "github") continue;
      const data = await scanModule(mod, sid, context);
      if (data) allData[mod.key] = data;
      await new Promise(r => setTimeout(r, 300));
    }

    addLog("─".repeat(36));
    if (!repoOnly && normalizedUrl) {
      setModuleStatuses(p => ({ ...p, risk: "scanning" }));
      setModuleProgress(p => ({ ...p, risk: 10 }));
      const riskTicker = runProgressTicks("risk");
      try {
        const rr = await fetch(`${API}/scan/risk-report`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scan_id: sid, url: normalizedUrl, headers: allData.header, tls: allData.tls, ports: allData.ports, directories: allData.directories, business: allData.business, cloud: allData.cloud }) });
        const rj = await rr.json();
        clearInterval(riskTicker);
        setModuleProgress(p => ({ ...p, risk: 100 }));
        setModuleStatuses(p => ({ ...p, risk: "done" }));
        setRiskData({ ...rj, scan_id: sid });
        addLog(`RISK ENGINE — Grade: ${rj.overall_grade} (${rj.overall_score}/100)`);
      } catch {
        clearInterval(riskTicker);
        setModuleStatuses(p => ({ ...p, risk: "done" }));
        addLog("Risk engine unavailable");
      }
    } else {
      setModuleProgress(p => ({ ...p, risk: 100 }));
      setModuleStatuses(p => ({ ...p, risk: "done" }));
      addLog(repoOnly ? "RISK ENGINE — Skipped (repository-only mode)" : "RISK ENGINE — Skipped (web target not provided)");
    }

    addLog("BREACH PROTOCOL COMPLETE");
    setPhase("results");
  };

  const startRepoScan = async (repoUrl) => {
    await startScan({ url: "", repoUrl, repoOnly: true });
  };

  const handleReset = () => { setPhase("landing"); setScanMode("full"); setTarget(""); setRepoTarget(""); setResults({}); setRiskData(null); };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)", position: "relative", overflowX: "hidden" }}>
      <ParticleField />
      <div className="grid-floor" />

      {/* NAV */}
      <nav style={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 100, borderBottom: "1px solid rgba(0,255,65,0.08)", background: "rgba(5,5,16,0.85)", backdropFilter: "blur(20px)", padding: "0 24px", height: "52px", display: "flex", alignItems: "center", gap: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <svg width="20" height="20" viewBox="0 0 40 40" fill="none">
            <polygon points="20,2 38,11 38,29 20,38 2,29 2,11" stroke="#00ff41" strokeWidth="1.5" fill="none" style={{ filter: "drop-shadow(0 0 4px rgba(0,255,65,0.5))" }} />
            <circle cx="20" cy="20" r="4" fill="#00ff41" />
          </svg>
          <span style={{ fontFamily: "var(--font-disp)", fontSize: "13px", fontWeight: 700, color: "#00ff41", letterSpacing: "0.1em", textShadow: "0 0 10px rgba(0,255,65,0.4)" }}>E-WMEAP</span>
        </div>
        {target && <span style={{ color: "rgba(0,255,65,0.55)", fontSize: "10px", fontFamily: "var(--font-mono)" }}>{target}</span>}
        {!target && repoTarget && <span style={{ color: "rgba(139,92,246,0.45)", fontSize: "10px", fontFamily: "var(--font-mono)" }}>{repoTarget}</span>}
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: "12px" }}>
          {phase === "scanning" && <span style={{ color: "#00ff41", fontSize: "10px", fontFamily: "var(--font-mono)", display: "flex", alignItems: "center", gap: "6px" }}><span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#00ff41", display: "inline-block", animation: "statusPulse 1s infinite" }} />SCANNING</span>}
          {phase === "results" && riskData && <span style={{ color: gradeColor(riskData.overall_grade), fontSize: "12px", fontFamily: "var(--font-disp)", fontWeight: 700 }}>GRADE: {riskData.overall_grade}</span>}
          {phase !== "landing" && <button onClick={handleReset} style={{ padding: "6px 14px", background: "transparent", border: "1px solid rgba(0,255,65,0.3)", borderRadius: "6px", color: "rgba(0,255,65,0.82)", fontFamily: "var(--font-mono)", fontSize: "10px", cursor: "pointer", letterSpacing: "0.1em" }}>RESET</button>}
        </div>
      </nav>

      <main style={{ paddingTop: "52px", position: "relative", zIndex: 5 }}>

        {/* ── LANDING ── */}
        {phase === "landing" && (
          <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "40px 24px" }}>
            <div style={{ width: "100%", maxWidth: "680px" }}>
              <HeroInput onScan={startScan} onRepoScan={startRepoScan} scanning={false} />
            </div>
          </div>
        )}

        {/* ── SCANNING ── */}
        {phase === "scanning" && (
          <div style={{ position: "relative", height: "calc(100vh - 52px)", overflow: "hidden" }}>
            <div style={{ position: "absolute", inset: 0, opacity: 0.35, pointerEvents: "none" }}>
              <ThreeScene phase="scanning" />
            </div>

            <div style={{ position: "relative", zIndex: 2, height: "100%", padding: "12px", display: "flex", flexDirection: "column" }}>
              <div style={{ padding: "10px 14px", marginBottom: "10px", background: "rgba(3,8,15,0.8)", border: "1px solid rgba(0,255,65,0.2)", borderRadius: "10px", fontFamily: "var(--font-mono)", fontSize: "11px", color: "rgba(226,232,240,0.92)", letterSpacing: "0.08em" }}>
                <span style={{ color: "#00ff41", fontWeight: 700 }}>TARGET ACQUIRED</span>
                {target && <span style={{ marginLeft: "10px", color: "#00ff41" }}>{target}</span>}
                {repoTarget && <span style={{ marginLeft: "10px", color: "#c4b5fd" }}>{repoTarget}</span>}
              </div>

              <div style={{ flex: 1, background: "rgba(0,5,0,0.45)", border: "1px solid rgba(0,255,65,0.2)", borderRadius: "12px", overflow: "hidden" }}>
                <ScanTerminal target={target} moduleStatuses={moduleStatuses} moduleProgress={moduleProgress} moduleFindings={moduleFindings} liveLog={liveLog} phase="scanning" />
              </div>
            </div>
          </div>
        )}

        {/* ── RESULTS ── */}
        {phase === "results" && (
          scanMode === "repo" ? (
            <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "24px" }}>
              <div style={{ marginBottom: "16px", padding: "10px 14px", border: "1px solid rgba(167,139,250,0.3)", borderRadius: "10px", background: "rgba(30,20,55,0.35)", color: "#c4b5fd", fontFamily: "var(--font-mono)", fontSize: "11px", letterSpacing: "0.08em" }}>
                REPOSITORY-ONLY RESULTS
              </div>
              {results.github
                ? <GitHubScanner data={results.github} loading={false} />
                : <div style={{ textAlign: "center", padding: "48px", color: "rgba(167,139,250,0.45)", fontFamily: "var(--font-mono)", fontSize: "11px", letterSpacing: "0.15em" }}>NO GITHUB RESULTS AVAILABLE</div>
              }
            </div>
          ) : (
            <div style={{ maxWidth: "1400px", margin: "0 auto", padding: "24px" }}>
              <div style={{ marginBottom: "20px" }}>
                <ScanCompleteBanner report={riskData} onReset={handleReset} />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: "16px", marginBottom: "20px" }}>
                <div style={{ background: "rgba(0,5,0,0.4)", border: "1px solid rgba(0,255,65,0.08)", borderRadius: "12px", overflow: "hidden", maxHeight: "320px" }}>
                  <ScanTerminal target={target} moduleStatuses={moduleStatuses} moduleProgress={moduleProgress} moduleFindings={moduleFindings} liveLog={liveLog} phase="complete" />
                </div>
                <div style={{ background: "rgba(0,5,0,0.4)", border: "1px solid rgba(0,255,65,0.08)", borderRadius: "12px", overflow: "hidden", height: "320px" }}>
                  <ThreeScene phase="results" scanData={riskData} />
                </div>
              </div>

              {error && <div style={{ background: "rgba(255,0,64,0.08)", border: "1px solid rgba(255,0,64,0.3)", borderRadius: "10px", padding: "12px 16px", color: "#ff0040", fontSize: "12px", fontFamily: "var(--font-mono)", marginBottom: "16px" }}>✕ {error}</div>}

              {/* ── Module tabs — bigger, cleaner ── */}
              <div style={{ display: "flex", gap: "8px", marginBottom: "20px", flexWrap: "wrap", padding: "16px", background: "rgba(0,5,0,0.4)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: "14px" }}>
                <span style={{ color: "rgba(255,255,255,0.2)", fontSize: "10px", fontFamily: "var(--font-mono)", letterSpacing: "0.2em", alignSelf: "center", marginRight: "8px" }}>VIEW MODULE →</span>
                {MODULE_TABS.map(tab => {
                  const hasData = tab.key === "risk" ? !!riskData : !!results[tab.key];
                  const isActive = activeModule === tab.key;
                  const findingCount = tab.key === "risk" ? (riskData?.total_findings || 0) :
                    tab.key === "header" ? (results.header?.findings?.length || 0) :
                      tab.key === "ports" ? (results.ports?.open_ports?.length || 0) :
                        tab.key === "directories" ? (results.directories?.total_found || 0) :
                          tab.key === "business" ? ((results.business?.cors?.findings?.length || 0) + (results.business?.jwt?.findings?.length || 0) + (results.business?.graphql?.findings?.length || 0)) :
                            tab.key === "cloud" ? ((results.cloud?.s3?.findings?.length || 0) + (results.cloud?.subdomains?.takeover_findings?.length || 0) + (results.cloud?.services?.findings?.length || 0)) : 0;
                  return (
                    <button key={tab.key}
                      onClick={() => setActiveModule(isActive ? null : tab.key)}
                      disabled={!hasData}
                      style={{
                        padding: "10px 20px",
                        background: isActive ? `${tab.color}20` : "rgba(255,255,255,0.03)",
                        border: `1px solid ${isActive ? tab.color : "rgba(255,255,255,0.08)"}`,
                        borderRadius: "8px",
                        color: hasData ? (isActive ? tab.color : "rgba(255,255,255,0.5)") : "rgba(255,255,255,0.1)",
                        fontFamily: "var(--font-mono)",
                        fontSize: "11px",
                        letterSpacing: "0.1em",
                        fontWeight: isActive ? 700 : 400,
                        cursor: hasData ? "pointer" : "not-allowed",
                        transition: "all 0.2s",
                        boxShadow: isActive ? `0 0 16px ${tab.color}25` : "none",
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}>
                      {tab.label}
                      {hasData && findingCount > 0 && (
                        <span style={{
                          background: isActive ? `${tab.color}30` : "rgba(255,255,255,0.08)",
                          color: isActive ? tab.color : "rgba(255,255,255,0.4)",
                          borderRadius: "4px",
                          padding: "1px 6px",
                          fontSize: "10px",
                          fontWeight: 700,
                        }}>
                          {findingCount}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
              {/* Module results */}
              <div>
                {activeModule === "risk" && riskData && <div className="fade-up"><RiskDashboard data={riskData} loading={false} /></div>}
                {activeModule === "header" && results.header && <div className="fade-up"><HeaderScanner data={results.header} tlsData={results.tls} loading={false} /></div>}
                {activeModule === "ports" && results.ports && <div className="fade-up"><PortScanner data={results.ports} loading={false} /></div>}
                {activeModule === "directories" && results.directories && <div className="fade-up"><DirectoryScanner data={results.directories} loading={false} /></div>}
                {activeModule === "business" && results.business && <div className="fade-up"><BusinessLogicScanner data={results.business} loading={false} /></div>}
                {activeModule === "cloud" && results.cloud && <div className="fade-up"><CloudScanner data={results.cloud} loading={false} /></div>}
                {activeModule === "github" && results.github && <div className="fade-up"><GitHubScanner data={results.github} loading={false} /></div>}
                {!activeModule && <div style={{ textAlign: "center", padding: "48px", color: "rgba(148,163,184,0.62)", fontFamily: "var(--font-mono)", fontSize: "11px", letterSpacing: "0.15em" }}>SELECT A MODULE TAB ABOVE TO VIEW DETAILED RESULTS</div>}
              </div>
            </div>
          )
        )}
      </main>
    </div>
  );
}
// frontend/src/components/modules/RiskDashboard.jsx
// Module 8 — Risk Engine Dashboard
// Shows: score ring, grade, severity donut, module summary, chains, remediation priority

import { useState } from "react";
import { SEVERITY_STYLES } from "../ui/SeverityBadge";

const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, None: 4 };
const SEV_COLORS_HEX = {
  Critical: "#ef4444", High: "#f97316", Medium: "#f59e0b",
  Low: "#60a5fa", None: "#34d399", Info: "#94a3b8",
};

// ── Score Ring SVG ────────────────────────────────────────────────────────────
function ScoreRing({ score, grade }) {
  const r      = 56;
  const circ   = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const gradColor =
    grade === "A+" || grade === "A" ? "#34d399" :
    grade === "B"  ? "#60a5fa" :
    grade === "C"  ? "#f59e0b" :
    grade === "D"  ? "#f97316" : "#ef4444";

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="140" viewBox="0 0 140 140">
        {/* Track */}
        <circle cx="70" cy="70" r={r} fill="none" stroke="#1e293b" strokeWidth="10"/>
        {/* Progress */}
        <circle
          cx="70" cy="70" r={r} fill="none"
          stroke={gradColor} strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dashoffset 1.2s ease" }}
        />
        {/* Grade */}
        <text x="70" y="62" textAnchor="middle" fill="white"
          fontSize="30" fontWeight="900" fontFamily="monospace">{grade}</text>
        {/* Score */}
        <text x="70" y="82" textAnchor="middle" fill={gradColor}
          fontSize="16" fontWeight="700" fontFamily="monospace">{score}</text>
        <text x="70" y="95" textAnchor="middle" fill="#475569"
          fontSize="9" fontFamily="monospace">/100</text>
      </svg>
      <p className="text-[10px] uppercase tracking-widest text-slate-500 mt-1">Security Score</p>
    </div>
  );
}

// ── Severity Donut ────────────────────────────────────────────────────────────
function SeverityDonut({ counts }) {
  const order  = ["Critical", "High", "Medium", "Low"];
  const total  = order.reduce((s, k) => s + (counts[k] ?? 0), 0);
  if (total === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-32">
        <p className="text-emerald-400 text-2xl font-black">✓</p>
        <p className="text-xs text-slate-500 mt-1">No findings</p>
      </div>
    );
  }

  const r   = 48;
  const cx  = 70;
  const cy  = 70;
  let   angle = -Math.PI / 2;
  const slices = [];

  order.forEach(sev => {
    const n    = counts[sev] ?? 0;
    if (!n) return;
    const frac = n / total;
    const span = frac * 2 * Math.PI;
    const x1   = cx + r * Math.cos(angle);
    const y1   = cy + r * Math.sin(angle);
    angle      += span;
    const x2   = cx + r * Math.cos(angle);
    const y2   = cy + r * Math.sin(angle);
    const large= span > Math.PI ? 1 : 0;
    slices.push({
      path: `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`,
      color: SEV_COLORS_HEX[sev],
      sev, n,
    });
  });

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="140" viewBox="0 0 140 140">
        {slices.map((s, i) => (
          <path key={i} d={s.path} fill={s.color} opacity="0.9"/>
        ))}
        {/* Donut hole */}
        <circle cx={cx} cy={cy} r={r * 0.52} fill="#0a0f1e"/>
        <text x={cx} y={cy+4} textAnchor="middle" fill="white"
          fontSize="16" fontWeight="900" fontFamily="monospace">{total}</text>
        <text x={cx} y={cy+15} textAnchor="middle" fill="#475569"
          fontSize="8" fontFamily="monospace">findings</text>
      </svg>
      {/* Legend */}
      <div className="flex gap-3 flex-wrap justify-center mt-2">
        {order.map(sev => (counts[sev] ?? 0) > 0 ? (
          <div key={sev} className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full" style={{ background: SEV_COLORS_HEX[sev] }}/>
            <span className="text-[10px] text-slate-400">{sev} ({counts[sev]})</span>
          </div>
        ) : null)}
      </div>
      <p className="text-[10px] uppercase tracking-widest text-slate-500 mt-1">Severity Distribution</p>
    </div>
  );
}

// ── Threat Intel Card ─────────────────────────────────────────────────────────
function ThreatIntelCard({ data }) {
  if (!data) return null;
  const { threat_level, threat_indicators = [], shodan, otx, abuseipdb, ip, api_keys_configured } = data;

  const levelColor =
    threat_level === "High"   ? "text-red-400 bg-red-950/40 border-red-800/50" :
    threat_level === "Medium" ? "text-amber-400 bg-amber-950/40 border-amber-800/50" :
    "text-emerald-400 bg-emerald-950/30 border-emerald-800/40";

  const anyConfigured = Object.values(api_keys_configured ?? {}).some(Boolean);

  return (
    <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 overflow-hidden">
      <div className="px-4 py-3 bg-slate-800/60 border-b border-slate-700/40 flex items-center justify-between">
        <span className="text-xs font-bold text-slate-200 uppercase tracking-widest">Threat Intelligence</span>
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${levelColor}`}>
          {threat_level} Threat
        </span>
      </div>

      {!anyConfigured && (
        <div className="px-4 py-3 text-xs text-amber-300 bg-amber-950/20 border-b border-amber-800/30">
          ⚠ No API keys configured. Set SHODAN_API_KEY, OTX_API_KEY, ABUSEIPDB_API_KEY for full threat intel.
        </div>
      )}

      <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Shodan */}
        <div>
          <p className="text-[10px] uppercase tracking-widest text-blue-400 font-semibold mb-2">Shodan</p>
          {!shodan?.available ? (
            <p className="text-[10px] text-slate-600">Not configured</p>
          ) : shodan?.indexed ? (
            <>
              <p className="text-xs text-slate-300 mb-1">{shodan.org} — {shodan.country}</p>
              {shodan.ports?.length > 0 && (
                <p className="text-[10px] text-slate-500">Ports: {shodan.ports.slice(0,6).join(", ")}</p>
              )}
              {shodan.vulns?.length > 0 && (
                <p className="text-[10px] text-red-400 mt-1">CVEs: {shodan.vulns.slice(0,3).join(", ")}</p>
              )}
              <p className="text-[10px] text-amber-400 mt-1">{shodan.risk_note}</p>
            </>
          ) : (
            <p className="text-[10px] text-emerald-400">Not indexed by Shodan</p>
          )}
        </div>

        {/* OTX */}
        <div>
          <p className="text-[10px] uppercase tracking-widest text-purple-400 font-semibold mb-2">AlienVault OTX</p>
          {!otx?.available ? (
            <p className="text-[10px] text-slate-600">Not configured</p>
          ) : (
            <>
              <p className={`text-xs font-semibold ${otx.is_malicious ? "text-red-400" : "text-emerald-400"}`}>
                {otx.is_malicious ? `⚠ ${otx.pulse_count} threat pulse(s)` : "✓ No threat pulses"}
              </p>
              <p className="text-[10px] text-slate-500 mt-1">IP: {ip ?? "—"}</p>
            </>
          )}
        </div>

        {/* AbuseIPDB */}
        <div>
          <p className="text-[10px] uppercase tracking-widest text-orange-400 font-semibold mb-2">AbuseIPDB</p>
          {!abuseipdb?.available ? (
            <p className="text-[10px] text-slate-600">Not configured</p>
          ) : (
            <>
              <div className="flex items-center gap-2">
                <div className="flex-1 h-1.5 rounded-full bg-slate-700 overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${abuseipdb.abuse_score}%`,
                      background: abuseipdb.abuse_score > 50 ? "#ef4444" : abuseipdb.abuse_score > 25 ? "#f97316" : "#34d399"
                    }}
                  />
                </div>
                <span className="text-xs font-mono text-slate-300">{abuseipdb.abuse_score}%</span>
              </div>
              <p className="text-[10px] text-slate-500 mt-1">{abuseipdb.isp} · {abuseipdb.usage_type}</p>
            </>
          )}
        </div>
      </div>

      {threat_indicators.length > 0 && (
        <div className="px-4 pb-3">
          <p className="text-[10px] uppercase tracking-widest text-red-400 font-semibold mb-1">Threat Indicators</p>
          {threat_indicators.map((t, i) => (
            <p key={i} className="text-xs text-red-300 flex gap-2">
              <span className="text-red-600">▸</span>{t}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Chain Visualization ───────────────────────────────────────────────────────
function ChainCard({ chain }) {
  const [exp, setExp] = useState(false);
  return (
    <div
      onClick={() => setExp(!exp)}
      className="cursor-pointer rounded-xl border border-red-900/50 bg-red-950/20 overflow-hidden hover:bg-red-950/30 transition-colors"
    >
      <div className="flex items-center gap-3 px-4 py-3">
        <span className="text-red-400 text-sm">⛓</span>
        <div className="flex-1 min-w-0">
          <p className="text-xs font-bold text-red-200">{chain.name}</p>
          <div className="flex gap-2 mt-1 flex-wrap">
            {chain.components?.map((c, i) => (
              <span key={i} className="text-[10px] font-mono px-2 py-0.5 bg-red-900/40 text-red-300 border border-red-800/40 rounded">
                {c}
              </span>
            ))}
          </div>
        </div>
        <div className="text-right flex-shrink-0">
          <p className="text-xs font-bold text-red-400">{chain.severity}</p>
          <p className="text-[10px] font-mono text-slate-500">CVSS {chain.cvss?.score}</p>
        </div>
        <span className={`text-slate-500 text-xs transition-transform ${exp ? "rotate-180" : ""}`}>▾</span>
      </div>

      {exp && (
        <div className="px-4 pb-4 border-t border-red-900/30 pt-3 space-y-2">
          <p className="text-xs text-slate-300 leading-relaxed">{chain.description}</p>
          <div className="bg-red-950/40 border border-red-900/40 rounded px-3 py-2">
            <p className="text-[10px] uppercase tracking-widest text-red-400 font-semibold mb-0.5">Impact</p>
            <p className="text-xs text-slate-300">{chain.impact}</p>
          </div>
          <div className="bg-emerald-950/30 border border-emerald-900/40 rounded px-3 py-2">
            <p className="text-[10px] uppercase tracking-widest text-emerald-400 font-semibold mb-0.5">Remediation</p>
            <p className="text-xs text-slate-300">{chain.remediation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Module Summary Accordion ──────────────────────────────────────────────────
function ModuleAccordion({ modules }) {
  const [open, setOpen] = useState(null);
  if (!modules?.length) return null;

  return (
    <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden divide-y divide-slate-700/30">
      {modules.map((mod, i) => {
        const s = SEVERITY_STYLES[mod.severity] ?? SEVERITY_STYLES.None;
        const isOpen = open === i;
        return (
          <div key={i}>
            <div
              onClick={() => setOpen(isOpen ? null : i)}
              className="flex items-center gap-3 px-4 py-3.5 cursor-pointer hover:bg-slate-700/20 transition-colors"
            >
              <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.dot}`}/>
              <span className="text-xs font-semibold text-slate-200 flex-1">{mod.name}</span>
              <span className="text-[10px] text-slate-500 tabular-nums">{mod.count} finding{mod.count !== 1 ? "s" : ""}</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${s.badge}`}>{mod.severity}</span>
              <span className={`text-slate-500 text-xs transition-transform ${isOpen ? "rotate-180" : ""}`}>▾</span>
            </div>
            {isOpen && mod.summary && (
              <div className="px-5 pb-3 pt-1 bg-slate-900/40 border-t border-slate-700/20">
                <p className="text-xs text-slate-400 leading-relaxed">{mod.summary}</p>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Remediation Priority List ─────────────────────────────────────────────────
function RemediationList({ items }) {
  if (!items?.length) return null;
  return (
    <div className="space-y-2">
      {items.slice(0, 10).map((item, i) => {
        const s = SEVERITY_STYLES[item.severity] ?? SEVERITY_STYLES.Info;
        const barWidth = Math.round((item.cvss_score / 10) * 100);
        return (
          <div key={i} className={`rounded-lg border bg-slate-800/20 px-4 py-3 ${
            item.is_chain ? "border-red-900/50" : "border-slate-700/40"
          }`}>
            <div className="flex items-start gap-3">
              <span className={`text-sm font-black font-mono w-6 flex-shrink-0 ${s.text}`}>
                {String(i+1).padStart(2,"0")}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className={`text-xs font-semibold truncate ${item.is_chain ? "text-red-300" : "text-slate-200"}`}>
                    {item.is_chain && "⛓ "}{item.title}
                  </span>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border flex-shrink-0 ${s.badge}`}>
                    {item.severity}
                  </span>
                </div>
                {/* CVSS bar */}
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-1.5 rounded-full bg-slate-700 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{ width: `${barWidth}%`, background: s.dot.replace("bg-","").includes("red") ? "#ef4444" : SEV_COLORS_HEX[item.severity] ?? "#94a3b8" }}
                    />
                  </div>
                  <span className="text-[10px] font-mono text-slate-400 w-8 text-right">{item.cvss_score}</span>
                  <span className="text-[10px] text-slate-600">{item.module}</span>
                </div>
                {item.recommendation && (
                  <p className="text-[10px] text-slate-500 mt-1 truncate">{item.recommendation}</p>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── PDF Download Button ───────────────────────────────────────────────────────
function PdfDownloadButton({ scanId, target }) {
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const download = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`http://127.0.0.1:5000/scan/report/pdf/${scanId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = `ewmeap_report_${scanId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError("PDF generation failed: " + e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <button
        onClick={download}
        disabled={loading}
        className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500
          text-white text-xs font-bold rounded-xl transition-all
          disabled:opacity-40 disabled:cursor-not-allowed
          shadow-[0_0_16px_rgba(59,130,246,0.3)]"
      >
        {loading ? (
          <>
            <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
            </svg>
            Generating PDF…
          </>
        ) : (
          <>📄 Download PDF Report</>
        )}
      </button>
      {error && <p className="text-[10px] text-red-400 mt-1">{error}</p>}
    </div>
  );
}

// ── Loading skeleton ──────────────────────────────────────────────────────────
function LoadingSkeleton() {
  return (
    <section className="mb-10 animate-pulse">
      <div className="flex items-center gap-3 mb-5">
        <div className="w-1 h-6 rounded-full bg-slate-700"/>
        <div className="h-4 w-48 bg-slate-700 rounded"/>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        {[...Array(4)].map((_,i) => <div key={i} className="h-24 bg-slate-800/40 rounded-xl border border-slate-700/40"/>)}
      </div>
      <div className="h-64 bg-slate-800/20 rounded-xl border border-slate-700/40"/>
    </section>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function RiskDashboard({ data, loading }) {
  const [activeSection, setActiveSection] = useState("overview");

  if (loading) return <LoadingSkeleton/>;
  if (!data)   return null;

  if (data.error) {
    return (
      <section className="mb-10">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-1 h-6 rounded-full bg-indigo-500"/>
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">Risk Dashboard</h2>
        </div>
        <div className="bg-red-950/30 border border-red-800/40 rounded-xl px-5 py-4 text-sm text-red-300">{data.error}</div>
      </section>
    );
  }

  const {
    overall_score, overall_grade, severity_counts, total_findings,
    total_chains, chains = [], priority_list = [], module_summary = [],
    threat_intel, executive_summary, scan_id, target,
  } = data;

  const SECTIONS = [
    { id: "overview",     label: "Overview",    icon: "◈" },
    { id: "chains",       label: "Chains",      icon: "⛓",  badge: total_chains },
    { id: "priority",     label: "Priority",    icon: "⚡" },
    { id: "modules",      label: "Modules",     icon: "⬡" },
    { id: "threat_intel", label: "Threat Intel",icon: "🛡" },
  ];

  return (
    <section className="mb-10">
      {/* ── Header ── */}
      <div className="flex items-center gap-3 mb-5 flex-wrap">
        <div className="w-1 h-6 rounded-full bg-indigo-500"/>
        <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">Risk Dashboard</h2>
        <span className="text-xs text-slate-500">{total_findings} findings · {total_chains} chains</span>
        <div className="ml-auto">
          {scan_id && <PdfDownloadButton scanId={scan_id} target={target}/>}
        </div>
      </div>

      {/* ── Overview strip ── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        <ScoreRing score={overall_score} grade={overall_grade}/>
        <SeverityDonut counts={severity_counts}/>
        {/* Executive summary */}
        <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 p-4 flex flex-col justify-center">
          <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Assessment Summary</p>
          <p className="text-xs text-slate-300 leading-relaxed">
            {executive_summary?.narrative ?? "No narrative available."}
          </p>
          {executive_summary?.immediate_actions?.length > 0 && (
            <div className="mt-3">
              <p className="text-[10px] uppercase tracking-widest text-emerald-400 font-semibold mb-1.5">
                Immediate Actions
              </p>
              {executive_summary.immediate_actions.slice(0,3).map((a, i) => (
                <p key={i} className="text-[10px] text-slate-400 flex gap-1.5 mb-1">
                  <span className="text-emerald-600">▸</span>{a}
                </p>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Section tabs ── */}
      <div className="flex gap-2 mb-5 flex-wrap">
        {SECTIONS.map(sec => (
          <button key={sec.id} onClick={() => setActiveSection(sec.id)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg border text-xs font-semibold transition-all ${
              activeSection === sec.id
                ? "bg-indigo-900/50 border-indigo-600/60 text-indigo-300"
                : "bg-slate-800/40 border-slate-700/40 text-slate-400 hover:border-slate-500"
            }`}>
            <span>{sec.icon}</span>
            <span>{sec.label}</span>
            {sec.badge > 0 && (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-red-900/60 text-red-300 border border-red-700/40">
                {sec.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Section content ── */}
      {activeSection === "overview" && (
        <div className="space-y-4">
          <p className="text-xs font-bold text-slate-300 uppercase tracking-widest mb-3">Module Overview</p>
          <ModuleAccordion modules={module_summary}/>
        </div>
      )}

      {activeSection === "chains" && (
        <div className="space-y-3">
          {chains.length === 0 ? (
            <div className="rounded-xl border border-emerald-800/40 bg-emerald-950/20 px-5 py-10 text-center">
              <p className="text-emerald-400 font-semibold text-sm">✓ No vulnerability chains detected</p>
              <p className="text-slate-500 text-xs mt-1">No combinations of findings create escalated risk</p>
            </div>
          ) : (
            chains.map((c, i) => <ChainCard key={i} chain={c}/>)
          )}
        </div>
      )}

      {activeSection === "priority" && (
        <div>
          <p className="text-xs text-slate-500 mb-3">
            Sorted by CVSS score — address Critical items first
          </p>
          <RemediationList items={priority_list}/>
        </div>
      )}

      {activeSection === "modules" && (
        <ModuleAccordion modules={module_summary}/>
      )}

      {activeSection === "threat_intel" && (
        <ThreatIntelCard data={threat_intel}/>
      )}
    </section>
  );
}
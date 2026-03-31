// components/modules/HeaderScanner.jsx
// Module 1 — Security Header & TLS Analysis
// Displays results from /scan/header and /scan/tls endpoints

import { useState } from "react";
import { SeverityBadge, StatusBadge, SEVERITY_STYLES } from "../ui/SeverityBadge";

/* ─── Small helpers ──────────────────────────────────────────────────────── */

function ScoreRing({ score }) {
  // score: 0-100
  const grade =
    score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : score >= 35 ? "D" : "F";
  const gradeColor =
    grade === "A" ? "text-emerald-400" :
    grade === "B" ? "text-blue-400" :
    grade === "C" ? "text-amber-400" :
    grade === "D" ? "text-orange-400" : "text-red-400";

  const r = 36;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="96" height="96" viewBox="0 0 96 96">
        {/* track */}
        <circle cx="48" cy="48" r={r} fill="none" stroke="#1e293b" strokeWidth="8" />
        {/* progress */}
        <circle
          cx="48" cy="48" r={r}
          fill="none"
          stroke={
            grade === "A" ? "#34d399" : grade === "B" ? "#60a5fa" :
            grade === "C" ? "#fbbf24" : grade === "D" ? "#fb923c" : "#f87171"
          }
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          transform="rotate(-90 48 48)"
          style={{ transition: "stroke-dashoffset 1s ease" }}
        />
        <text x="48" y="44" textAnchor="middle" fill="white" fontSize="22" fontWeight="800" fontFamily="monospace">
          {grade}
        </text>
        <text x="48" y="60" textAnchor="middle" fill="#64748b" fontSize="11">
          {score}/100
        </text>
      </svg>
      <span className="text-xs text-slate-500 tracking-widest uppercase">Security Grade</span>
    </div>
  );
}

function StatPill({ label, value, color }) {
  return (
    <div className="flex flex-col items-center gap-0.5 px-4 py-2 rounded-lg bg-slate-800/60 border border-slate-700/50">
      <span className={`text-xl font-black font-mono ${color}`}>{value}</span>
      <span className="text-[10px] uppercase tracking-widest text-slate-500">{label}</span>
    </div>
  );
}

function CspAnalysis({ analysis }) {
  if (!analysis) return null;
  const { directives_found, dangerous_directives, missing_directives, poc_payload } = analysis;

  return (
    <div className="mt-3 rounded-lg border border-slate-700/50 bg-slate-800/40 overflow-hidden">
      <div className="px-4 py-2 bg-slate-800 border-b border-slate-700/50 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest text-slate-400 font-semibold">CSP Deep Analysis</span>
      </div>
      <div className="p-4 grid gap-3">

        {/* Dangerous directives */}
        {dangerous_directives?.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-red-400 font-semibold mb-1.5">⚠ Dangerous Directives</p>
            <div className="flex flex-wrap gap-2">
              {dangerous_directives.map((d, i) => (
                <span key={i} className="font-mono text-xs px-2 py-0.5 bg-red-900/40 text-red-300 border border-red-800/50 rounded">
                  {d}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Missing directives */}
        {missing_directives?.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-amber-400 font-semibold mb-1.5">Missing Directives</p>
            <div className="flex flex-wrap gap-2">
              {missing_directives.map((d, i) => (
                <span key={i} className="font-mono text-xs px-2 py-0.5 bg-amber-900/30 text-amber-300 border border-amber-800/40 rounded">
                  {d}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* PoC payload */}
        {poc_payload && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-purple-400 font-semibold mb-1.5">XSS PoC Payload (proof only)</p>
            <div className="bg-slate-900 rounded px-3 py-2 border border-purple-900/50">
              <code className="text-xs font-mono text-purple-300 break-all">{poc_payload}</code>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function TlsCard({ tls }) {
  if (!tls) return null;
  const gradeColor = {
    "A+": "text-emerald-400", A: "text-emerald-400", B: "text-blue-400",
    C: "text-amber-400", D: "text-orange-400", F: "text-red-400",
  };

  return (
    <div className="rounded-xl border border-slate-700/50 bg-slate-800/30 overflow-hidden">
      <div className="px-5 py-3 bg-slate-800/60 border-b border-slate-700/40 flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">TLS / SSL Analysis</span>
        {tls.grade && (
          <span className={`text-2xl font-black font-mono ${gradeColor[tls.grade] ?? "text-slate-300"}`}>
            {tls.grade}
          </span>
        )}
      </div>
      <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
        <div>
          <p className="text-slate-500 uppercase tracking-widest text-[10px] mb-1">Protocol</p>
          <p className="font-mono text-slate-200">{tls.protocol ?? "—"}</p>
        </div>
        <div>
          <p className="text-slate-500 uppercase tracking-widest text-[10px] mb-1">Cert Expiry</p>
          <p className={`font-mono ${tls.cert_expired ? "text-red-400" : "text-emerald-400"}`}>
            {tls.cert_expiry ?? "—"}
          </p>
        </div>
        <div>
          <p className="text-slate-500 uppercase tracking-widest text-[10px] mb-1">Issuer</p>
          <p className="font-mono text-slate-200 truncate">{tls.issuer ?? "—"}</p>
        </div>
        <div>
          <p className="text-slate-500 uppercase tracking-widest text-[10px] mb-1">HSTS Preload</p>
          <p className={`font-mono ${tls.hsts_preload ? "text-emerald-400" : "text-red-400"}`}>
            {tls.hsts_preload ? "Yes" : "No"}
          </p>
        </div>
      </div>
      {tls.issues?.length > 0 && (
        <div className="px-4 pb-4">
          <p className="text-[10px] uppercase tracking-widest text-red-400 font-semibold mb-2">Issues</p>
          <ul className="space-y-1">
            {tls.issues.map((issue, i) => (
              <li key={i} className="text-xs text-slate-300 flex gap-2">
                <span className="text-red-500 mt-0.5">▸</span>{issue}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/* ─── Main component ─────────────────────────────────────────────────────── */

export default function HeaderScanner({ data, tlsData, loading }) {
  const [expandedRow, setExpandedRow] = useState(null);

  if (loading) {
    return (
      <section className="mb-8 animate-pulse">
        <div className="h-6 w-48 bg-slate-700 rounded mb-4" />
        <div className="bg-slate-800/50 rounded-xl h-64 border border-slate-700/40" />
      </section>
    );
  }

  if (!data) return null;

  const { findings = [], total_headers_checked, score, observatory } = data;

  // compute summary counts
  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  const computedScore = score ?? Math.max(
    0,
    100 - (counts.High ?? 0) * 18 - (counts.Medium ?? 0) * 9 - (counts.Low ?? 0) * 3
  );

  return (
    <section className="mb-10">
      {/* ── Section header ── */}
      <div className="flex items-center gap-3 mb-5">
        <div className="w-1 h-6 rounded-full bg-blue-500" />
        <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
          Security Header Analysis
        </h2>
        <span className="ml-auto text-xs text-slate-500 font-medium tabular-nums">
          {total_headers_checked} headers checked
        </span>
      </div>

      {/* ── Summary row ── */}
      <div className="flex flex-col sm:flex-row gap-6 mb-6 items-start sm:items-center">
        <ScoreRing score={computedScore} />
        <div className="flex flex-wrap gap-3">
          {counts.High > 0 && <StatPill label="High" value={counts.High} color="text-red-400" />}
          {counts.Medium > 0 && <StatPill label="Medium" value={counts.Medium} color="text-amber-400" />}
          {counts.Low > 0 && <StatPill label="Low" value={counts.Low} color="text-blue-400" />}
          {counts.None > 0 && <StatPill label="Secure" value={counts.None} color="text-emerald-400" />}
        </div>

        {/* Mozilla Observatory badge */}
        {observatory && (
          <div className="ml-auto flex flex-col items-end gap-1">
            <span className="text-[10px] uppercase tracking-widest text-slate-500">Mozilla Observatory</span>
            <span className={`text-3xl font-black font-mono ${
              observatory.grade?.startsWith("A") ? "text-emerald-400" :
              observatory.grade?.startsWith("B") ? "text-blue-400" :
              observatory.grade?.startsWith("C") ? "text-amber-400" : "text-red-400"
            }`}>{observatory.grade ?? "—"}</span>
            <span className="text-xs text-slate-500">{observatory.score ?? "—"}/100</span>
          </div>
        )}
      </div>

      {/* ── TLS Card ── */}
      {tlsData && <div className="mb-5"><TlsCard tls={tlsData} /></div>}

      {/* ── Findings table ── */}
      <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden">
        {/* Table header */}
        <div className="grid grid-cols-[1.8fr_2.5fr_1fr_1fr] gap-0 bg-slate-800/70 border-b border-slate-700/50">
          {["Header", "Value", "Status", "Severity"].map((h) => (
            <div key={h} className="px-4 py-3 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              {h}
            </div>
          ))}
        </div>

        {/* Rows */}
        <div className="divide-y divide-slate-700/30">
          {findings.map((item, i) => {
            const isExpanded = expandedRow === i;
            const s = SEVERITY_STYLES[item.severity] ?? SEVERITY_STYLES.Info;

            return (
              <div key={i}>
                {/* Main row */}
                <div
                  className={`grid grid-cols-[1.8fr_2.5fr_1fr_1fr] gap-0 cursor-pointer
                    hover:bg-slate-700/20 transition-colors
                    ${isExpanded ? "bg-slate-700/20" : ""}
                    ${item.severity === "High" ? "border-l-2 border-red-500" :
                      item.severity === "Medium" ? "border-l-2 border-amber-500" :
                      item.severity === "Low" ? "border-l-2 border-blue-500" :
                      "border-l-2 border-transparent"}
                  `}
                  onClick={() => setExpandedRow(isExpanded ? null : i)}
                >
                  <div className="px-4 py-3.5 flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${s.dot}`} />
                    <span className="font-mono text-xs text-slate-200 truncate">{item.header}</span>
                  </div>
                  <div className="px-4 py-3.5 flex items-center">
                    <span className={`font-mono text-xs truncate max-w-full ${
                      item.value === "Not Present" ? "text-slate-600 italic" : "text-slate-400"
                    }`}>
                      {item.value || "Not Present"}
                    </span>
                  </div>
                  <div className="px-4 py-3.5 flex items-center">
                    <StatusBadge status={item.status} />
                  </div>
                  <div className="px-4 py-3.5 flex items-center justify-between">
                    <SeverityBadge level={item.severity} label={item.severity === "None" ? "OK" : item.severity} />
                    <span className={`text-slate-500 text-xs transition-transform ${isExpanded ? "rotate-180" : ""}`}>▾</span>
                  </div>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="px-5 pb-4 pt-1 bg-slate-900/50 border-t border-slate-700/30">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-2">
                      <div>
                        <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Impact</p>
                        <p className="text-xs text-slate-300 leading-relaxed">{item.impact}</p>
                      </div>
                      {item.recommendation && (
                        <div>
                          <p className="text-[10px] uppercase tracking-widest text-emerald-500 mb-1">Recommendation</p>
                          <p className="text-xs text-slate-300 leading-relaxed">{item.recommendation}</p>
                        </div>
                      )}
                    </div>

                    {/* CSP deep analysis */}
                    {item.header === "Content-Security-Policy" && item.csp_analysis && (
                      <CspAnalysis analysis={item.csp_analysis} />
                    )}

                    {/* Reference link */}
                    {item.reference && (
                      <a
                        href={item.reference}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 mt-2 text-[10px] text-blue-400 hover:text-blue-300 underline underline-offset-2"
                      >
                        MDN Reference ↗
                      </a>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
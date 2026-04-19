// src/components/ui/ScanTerminal.jsx
// Shows sequential module scanning with live status, progress bars, finding feed

import { useEffect, useRef, useState } from "react";

const MODULE_META = [
  { key: "header",      label: "HEADER ANALYSIS",          icon: "◈", color: "#00ff41" },
  { key: "tls",         label: "TLS/SSL INSPECTION",       icon: "🔒", color: "#0080ff" },
  { key: "ports",       label: "PORT RECONNAISSANCE",      icon: "⬡", color: "#ff0040" },
  { key: "directories", label: "DIRECTORY ENUMERATION",    icon: "📁", color: "#ffaa00" },
  { key: "business",    label: "BUSINESS LOGIC ANALYSIS",  icon: "⇄", color: "#aa00ff" },
  { key: "cloud",       label: "CLOUD MISCONFIGURATION",   icon: "☁", color: "#00aaff" },
  { key: "risk",        label: "RISK ENGINE",              icon: "⚡", color: "#ff6600" },
];

const SEV_COLOR = {
  Critical: "#ff0040",
  High:     "#ff6600",
  Medium:   "#ffaa00",
  Low:      "#0080ff",
  None:     "#00ff41",
};

function ProgressBar({ pct, color }) {
  return (
    <div className="h-1 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
      <div
        className="h-full rounded-full transition-all duration-300"
        style={{
          width: `${pct}%`,
          background: `linear-gradient(90deg, ${color}88, ${color})`,
          boxShadow: `0 0 8px ${color}`,
        }}
      />
    </div>
  );
}

function ModuleRow({ meta, status, pct, findingCount, severity }) {
  const isActive  = status === "scanning";
  const isDone    = status === "done";
  const isWaiting = status === "waiting";

  return (
    <div
      className="flex items-start gap-3 py-2.5 px-3 rounded-lg transition-all duration-300"
      style={{
        background: isActive ? `${meta.color}08` : "transparent",
        borderLeft: isActive ? `2px solid ${meta.color}` : "2px solid transparent",
      }}
    >
      {/* Status indicator */}
      <div className="flex-shrink-0 mt-0.5">
        {isWaiting && <span className="text-xs" style={{ color: "rgba(148,163,184,0.85)" }}>○</span>}
        {isActive  && (
          <span
            className="text-xs block"
            style={{ color: meta.color, animation: "statusPulse 1.2s ease-in-out infinite" }}
          >◉</span>
        )}
        {isDone && <span className="text-xs" style={{ color: "#00ff41" }}>✓</span>}
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-bold" style={{
            color: isWaiting ? "rgba(203,213,225,0.85)" : isDone ? "#00ff41" : meta.color,
            fontFamily: "var(--font-mono)",
          }}>
            {meta.icon} {meta.label}
          </span>
          {isDone && findingCount > 0 && (
            <span
              className="text-[9px] font-bold px-1.5 py-0.5 rounded"
              style={{ background: `${SEV_COLOR[severity] || "#64748b"}22`, color: SEV_COLOR[severity] || "#cbd5e1", border: `1px solid ${SEV_COLOR[severity] || "#64748b"}66` }}
            >
              {findingCount} findings
            </span>
          )}
          {isDone && findingCount === 0 && (
            <span className="text-[9px] px-1.5 py-0.5 rounded" style={{ background: "#00ff4111", color: "#00ff41", border: "1px solid #00ff4122" }}>
              clean
            </span>
          )}
        </div>
        {isActive && <ProgressBar pct={pct} color={meta.color} />}
        {isDone && <ProgressBar pct={100} color="#00ff41" />}
      </div>
    </div>
  );
}

function FindingFeedItem({ finding, index }) {
  const sev   = finding.severity || "Low";
  const color = SEV_COLOR[sev] || "#666";

  return (
    <div
      className="slam-in flex items-start gap-2 py-2 px-3 rounded text-xs"
      style={{
        background:  `${color}08`,
        borderLeft:  `2px solid ${color}`,
        animationDelay: `${index * 50}ms`,
      }}
    >
      <span className="font-bold flex-shrink-0" style={{ color }}>
        {sev === "Critical" ? "!!" : sev === "High" ? "!" : "›"}
      </span>
      <span style={{ color: "#d1d5db" }}>
        <span className="font-bold" style={{ color }}>
          [{sev.toUpperCase()}]
        </span>{" "}
        {finding.type || finding.header || finding.test || finding.path || "Finding"}
      </span>
    </div>
  );
}

export default function ScanTerminal({
  target,
  moduleStatuses,   // { header: "done"|"scanning"|"waiting", ... }
  moduleProgress,   // { header: 75, ... }  0-100
  moduleFindings,   // { header: [...], ... }
  liveLog,          // string[]
  phase,            // "idle"|"scanning"|"complete"
}) {
  const logRef    = useRef(null);
  const [visibleFindings, setVisibleFindings] = useState([]);

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [liveLog]);

  // Accumulate findings as they arrive
  useEffect(() => {
    const all = [];
    Object.entries(moduleFindings || {}).forEach(([mod, findings]) => {
      (findings || []).forEach(f => all.push({ ...f, _module: mod }));
    });
    // Sort by severity
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    all.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    setVisibleFindings(all.slice(0, 20));
  }, [moduleFindings]);

  const totalFindings = visibleFindings.length;
  const critCount     = visibleFindings.filter(f => f.severity === "Critical").length;

  return (
    <div className="flex flex-col h-full overflow-hidden" style={{ fontFamily: "var(--font-mono)", background: "rgba(3,8,15,0.72)", backdropFilter: "blur(2px)" }}>

      {/* ── Terminal header ── */}
      <div
        className="flex items-center justify-between px-4 py-3 border-b"
        style={{ borderColor: "rgba(0,255,65,0.15)", background: "rgba(0,255,65,0.03)" }}
      >
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: "#ff0040" }}/>
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: "#ffaa00" }}/>
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: "#00ff41" }}/>
          </div>
          <span className="text-[10px] uppercase tracking-widest" style={{ color: "#00ff4188" }}>
            BREACH_TERMINAL_v1.0
          </span>
        </div>
        {phase === "scanning" && (
          <span className="text-[10px] animate-pulse" style={{ color: "#00ff41" }}>
            ◉ ACTIVE
          </span>
        )}
        {phase === "complete" && (
          <span className="text-[10px]" style={{ color: "#00ff41" }}>
            ✓ COMPLETE
          </span>
        )}
      </div>

      {/* ── Target info ── */}
      {target && (
        <div className="px-4 py-2 border-b" style={{ borderColor: "rgba(0,255,65,0.08)" }}>
          <span className="text-[10px]" style={{ color: "rgba(148,163,184,0.95)" }}>TARGET › </span>
          <span className="text-[10px] font-bold" style={{ color: "#00ff41" }}>{target}</span>
        </div>
      )}

      <div className="flex-1 min-h-0 p-2" style={{ display: "grid", gridTemplateColumns: "minmax(280px, 34%) minmax(0, 66%)", gap: "8px" }}>
        {/* ── Left: Module list only ── */}
        <div className="rounded-lg border overflow-hidden min-h-0" style={{ borderColor: "rgba(0,255,65,0.2)", background: "rgba(0,255,65,0.04)" }}>
          <div className="px-3 py-1.5 border-b text-[10px] uppercase tracking-widest font-semibold" style={{ borderColor: "rgba(0,255,65,0.2)", color: "rgba(134,239,172,0.95)", background: "rgba(0,255,65,0.08)" }}>
            Module Status
          </div>
          <div className="px-2 py-2 overflow-y-auto" style={{ height: "100%" }}>
            {MODULE_META.map(meta => (
              <ModuleRow
                key={meta.key}
                meta={meta}
                status={(moduleStatuses || {})[meta.key] || "waiting"}
                pct={(moduleProgress || {})[meta.key] || 0}
                findingCount={((moduleFindings || {})[meta.key] || []).length}
                severity={
                  ((moduleFindings || {})[meta.key] || []).find(f => f.severity === "Critical") ? "Critical" :
                  ((moduleFindings || {})[meta.key] || []).find(f => f.severity === "High")     ? "High"     :
                  ((moduleFindings || {})[meta.key] || []).find(f => f.severity === "Medium")   ? "Medium"   : "Low"
                }
              />
            ))}
          </div>
        </div>

        {/* ── Right: Activity + Results ── */}
        <div className="min-h-0" style={{ display: "grid", gridTemplateRows: visibleFindings.length > 0 ? "minmax(160px, 1fr) minmax(140px, 0.9fr)" : "1fr", gap: "8px" }}>
          <div className="rounded-lg border overflow-hidden min-h-0" style={{ borderColor: "rgba(0,170,255,0.28)", background: "rgba(0,170,255,0.035)" }}>
            <div className="px-3 py-1.5 border-b text-[10px] uppercase tracking-widest font-semibold" style={{ borderColor: "rgba(0,170,255,0.22)", color: "rgba(125,211,252,0.95)", background: "rgba(0,170,255,0.08)" }}>
              Live Activity
            </div>
            <div
              ref={logRef}
              className="h-full px-4 py-3 overflow-y-auto"
            >
              {(liveLog || []).map((line, i) => (
                <div key={i} className="text-[10px] leading-5 terminal-text" style={{ opacity: 0.6 + (i / (liveLog.length || 1)) * 0.4 }}>
                  <span style={{ color: "rgba(148,163,184,0.95)" }}>$ </span>{line}
                </div>
              ))}
              {phase === "scanning" && (
                <div className="text-[10px] terminal-text cursor">
                  <span style={{ color: "rgba(148,163,184,0.95)" }}>$ </span>
                </div>
              )}
            </div>
          </div>

          {visibleFindings.length > 0 && (
            <div className="rounded-lg border overflow-y-auto min-h-0" style={{ borderColor: "rgba(255,0,64,0.22)", background: "rgba(255,0,64,0.045)" }}>
              <div className="flex items-center justify-between px-3 py-1.5 border-b" style={{ borderColor: "rgba(255,0,64,0.2)", background: "rgba(255,0,64,0.08)" }}>
                <span className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: "rgba(253,164,175,0.95)" }}>
                  Results Feed
                </span>
                <div className="flex gap-2">
                  {critCount > 0 && (
                    <span className="text-[9px] font-bold" style={{ color: "#ff0040" }}>
                      {critCount} CRITICAL
                    </span>
                  )}
                  <span className="text-[9px]" style={{ color: "rgba(226,232,240,0.85)" }}>
                    {totalFindings} total
                  </span>
                </div>
              </div>
              <div className="space-y-1 px-2 py-2">
                {visibleFindings.map((f, i) => (
                  <FindingFeedItem key={i} finding={f} index={i} />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
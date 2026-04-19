// src/components/ui/ScanCompleteBanner.jsx

import { useEffect, useState } from "react";

const GRADE_COLORS = {
  "A+": "#00ff41", "A": "#00ff41", "B": "#0080ff",
  "C":  "#ffaa00", "D": "#ff6600", "F": "#ff0040",
};

const GRADE_LABELS = {
  "A+": "EXCEPTIONAL",
  "A":  "EXCELLENT",
  "B":  "GOOD",
  "C":  "FAIR",
  "D":  "POOR",
  "F":  "CRITICAL",
};

function AnimatedCounter({ target, duration = 1800 }) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    if (!target) return;
    const start = Date.now();
    const tick = () => {
      const elapsed = Date.now() - start;
      const pct     = Math.min(elapsed / duration, 1);
      const eased   = 1 - Math.pow(1 - pct, 3);
      setValue(Math.round(target * eased));
      if (pct < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target, duration]);
  return <>{value}</>;
}

function ScoreRing({ score, grade }) {
  const color  = GRADE_COLORS[grade] || "#ff0040";
  const r      = 70;
  const circ   = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);

  return (
    <div style={{ position: "relative", display: "inline-flex", flexDirection: "column", alignItems: "center" }}>
      <svg width="180" height="180" viewBox="0 0 180 180">
        {/* Outer glow ring */}
        <circle cx="90" cy="90" r={r + 8} fill="none"
          stroke={color} strokeWidth="1" opacity="0.1" />
        {/* Track */}
        <circle cx="90" cy="90" r={r} fill="none"
          stroke="rgba(255,255,255,0.06)" strokeWidth="12" />
        {/* Progress */}
        <circle cx="90" cy="90" r={r}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          transform="rotate(-90 90 90)"
          style={{
            filter: `drop-shadow(0 0 12px ${color}) drop-shadow(0 0 24px ${color}66)`,
            transition: "stroke-dashoffset 2s cubic-bezier(0.22,1,0.36,1)"
          }}
        />
        {/* Score number */}
        <text x="90" y="82" textAnchor="middle"
          fill="white" fontSize="38" fontWeight="900" fontFamily="monospace">
          <AnimatedCounter target={score} />
        </text>
        {/* /100 label */}
        <text x="90" y="104" textAnchor="middle"
          fill="rgba(255,255,255,0.35)" fontSize="13" fontFamily="monospace">
          /100
        </text>
        {/* SCORE label */}
        <text x="90" y="122" textAnchor="middle"
          fill="rgba(255,255,255,0.2)" fontSize="9" fontFamily="monospace" letterSpacing="3">
          SCORE
        </text>
      </svg>
    </div>
  );
}

function SeverityBar({ label, value, color, maxVal }) {
  const pct = maxVal > 0 ? Math.min(100, (value / maxVal) * 100) : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
      {/* Label */}
      <span style={{
        color,
        fontSize:      "11px",
        letterSpacing: "0.12em",
        fontFamily:    "var(--font-mono)",
        fontWeight:    600,
        width:         "68px",
        flexShrink:    0,
      }}>
        {label}
      </span>

      {/* Bar track */}
      <div style={{
        flex:         1,
        height:       "6px",
        background:   "rgba(255,255,255,0.06)",
        borderRadius: "3px",
        overflow:     "hidden",
        minWidth:     "80px",
      }}>
        <div style={{
          width:        `${pct}%`,
          height:       "100%",
          background:   color,
          borderRadius: "3px",
          boxShadow:    `0 0 8px ${color}`,
          transition:   "width 1.2s cubic-bezier(0.22,1,0.36,1)",
        }} />
      </div>

      {/* Count */}
      <span style={{
        color,
        fontSize:   "20px",
        fontWeight: 900,
        fontFamily: "var(--font-mono)",
        width:      "32px",
        textAlign:  "right",
        flexShrink: 0,
        textShadow: `0 0 10px ${color}88`,
      }}>
        {value}
      </span>
    </div>
  );
}

export default function ScanCompleteBanner({ report, onReset }) {
  const [visible,   setVisible]   = useState(false);
  const [critFlash, setCritFlash] = useState(false);

  useEffect(() => {
    if (!report) return;
    const t1 = setTimeout(() => setVisible(true), 300);
    if ((report.severity_counts?.Critical || 0) > 0) {
      const t2 = setTimeout(() => setCritFlash(true), 500);
      return () => { clearTimeout(t1); clearTimeout(t2); };
    }
    return () => clearTimeout(t1);
  }, [report]);

  if (!report || !visible) return null;

  const grade      = report.overall_grade || "F";
  const score      = report.overall_score || 0;
  const gradeColor = GRADE_COLORS[grade]  || "#ff0040";
  const gradeLabel = GRADE_LABELS[grade]  || "UNKNOWN";
  const sevCounts  = report.severity_counts || {};
  const maxSev     = Math.max(
    sevCounts.Critical || 0,
    sevCounts.High     || 0,
    sevCounts.Medium   || 0,
    sevCounts.Low      || 0,
    1
  );

  const riskLevel =
    score < 40 ? "CRITICAL RISK"  :
    score < 60 ? "HIGH RISK"      :
    score < 75 ? "MEDIUM RISK"    :
    score < 90 ? "LOW RISK"       : "MINIMAL RISK";

  return (
    <>
      {/* Red flash overlay */}
      {critFlash && (
        <div className="red-flash-overlay"
          onAnimationEnd={() => setCritFlash(false)} />
      )}

      {/* ── Main banner ── */}
      <div
        className="banner-drop"
        style={{
          background:     "rgba(6,6,18,0.97)",
          border:         `1px solid ${gradeColor}28`,
          borderRadius:   "20px",
          backdropFilter: "blur(24px)",
          padding:        "40px 48px",
          position:       "relative",
          overflow:       "hidden",
          boxShadow:      `0 0 60px ${gradeColor}14, 0 40px 80px rgba(0,0,0,0.6)`,
        }}
      >

        {/* Background radial glow */}
        <div style={{
          position:      "absolute",
          inset:         0,
          background:    `radial-gradient(ellipse 60% 50% at 50% 0%, ${gradeColor}09, transparent 70%)`,
          pointerEvents: "none",
        }} />

        {/* Corner label */}
        <div style={{
          position:      "absolute",
          top:           "20px",
          right:         "24px",
          color:         `${gradeColor}55`,
          fontSize:      "9px",
          letterSpacing: "0.3em",
          fontFamily:    "var(--font-disp)",
          fontWeight:    700,
        }}>
          BREACH PROTOCOL — COMPLETE
        </div>

        {/* ── Layout: 3 columns ── */}
        <div style={{
          display:             "grid",
          gridTemplateColumns: "auto 1fr auto",
          gap:                 "48px",
          alignItems:          "center",
          position:            "relative",
        }}>

          {/* ── Left: Grade + Score ring ── */}
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "12px" }}>
            {/* Grade letter */}
            <div style={{
              fontFamily:    "var(--font-disp)",
              fontSize:      "96px",
              fontWeight:    900,
              color:         gradeColor,
              lineHeight:    1,
              textShadow:    `0 0 40px ${gradeColor}aa, 0 0 80px ${gradeColor}44`,
              letterSpacing: "-0.02em",
            }}>
              {grade}
            </div>
            <div style={{
              color:         gradeColor,
              fontSize:      "10px",
              letterSpacing: "0.3em",
              fontFamily:    "var(--font-disp)",
              fontWeight:    700,
              opacity:       0.7,
            }}>
              {gradeLabel}
            </div>

            {/* Score ring */}
            <ScoreRing score={score} grade={grade} />
          </div>

          {/* ── Centre: severity bars + meta ── */}
          <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>

            {/* Risk level */}
            <div>
              <div style={{
                color:         "rgba(255,255,255,0.35)",
                fontSize:      "10px",
                letterSpacing: "0.25em",
                fontFamily:    "var(--font-mono)",
                marginBottom:  "8px",
              }}>
                OVERALL RISK ASSESSMENT
              </div>
              <div style={{
                color:         gradeColor,
                fontSize:      "28px",
                fontFamily:    "var(--font-disp)",
                fontWeight:    700,
                letterSpacing: "0.08em",
                textShadow:    `0 0 20px ${gradeColor}66`,
              }}>
                {riskLevel}
              </div>
            </div>

            {/* Divider */}
            <div style={{ height: "1px", background: "rgba(255,255,255,0.06)" }} />

            {/* Severity bars */}
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div style={{ color: "rgba(255,255,255,0.3)", fontSize: "9px", letterSpacing: "0.25em", fontFamily: "var(--font-mono)", marginBottom: "4px" }}>
                FINDINGS BREAKDOWN
              </div>
              <SeverityBar label="CRITICAL" value={sevCounts.Critical || 0} color="#ff0040" maxVal={maxSev} />
              <SeverityBar label="HIGH"     value={sevCounts.High     || 0} color="#ff6600" maxVal={maxSev} />
              <SeverityBar label="MEDIUM"   value={sevCounts.Medium   || 0} color="#ffaa00" maxVal={maxSev} />
              <SeverityBar label="LOW"      value={sevCounts.Low      || 0} color="#0080ff" maxVal={maxSev} />
            </div>

            {/* Chains */}
            {(report.total_chains || 0) > 0 && (
              <div style={{
                display:      "flex",
                alignItems:   "center",
                gap:          "10px",
                padding:      "10px 16px",
                background:   "rgba(255,0,64,0.08)",
                border:       "1px solid rgba(255,0,64,0.2)",
                borderRadius: "8px",
              }}>
                <span style={{ fontSize: "16px" }}>⛓</span>
                <span style={{
                  color:         "#ff0040",
                  fontSize:      "12px",
                  fontFamily:    "var(--font-mono)",
                  fontWeight:    600,
                  letterSpacing: "0.08em",
                }}>
                  {report.total_chains} VULNERABILITY CHAIN{report.total_chains !== 1 ? "S" : ""} DETECTED
                </span>
              </div>
            )}
          </div>

          {/* ── Right: stats + actions ── */}
          <div style={{ display: "flex", flexDirection: "column", gap: "20px", minWidth: "200px" }}>

            {/* Total findings stat */}
            <div style={{
              padding:      "20px 24px",
              background:   "rgba(255,255,255,0.03)",
              border:       "1px solid rgba(255,255,255,0.07)",
              borderRadius: "12px",
              textAlign:    "center",
            }}>
              <div style={{
                color:         "white",
                fontSize:      "48px",
                fontWeight:    900,
                fontFamily:    "var(--font-mono)",
                lineHeight:    1,
                textShadow:    "0 0 20px rgba(255,255,255,0.2)",
              }}>
                {report.total_findings || 0}
              </div>
              <div style={{
                color:         "rgba(255,255,255,0.3)",
                fontSize:      "10px",
                letterSpacing: "0.2em",
                fontFamily:    "var(--font-mono)",
                marginTop:     "6px",
              }}>
                TOTAL FINDINGS
              </div>
            </div>

            {/* Scan ID */}
            {report.scan_id && (
              <div style={{ textAlign: "center" }}>
                <div style={{ color: "rgba(255,255,255,0.15)", fontSize: "9px", letterSpacing: "0.2em", fontFamily: "var(--font-mono)", marginBottom: "4px" }}>
                  SCAN ID
                </div>
                <div style={{ color: "rgba(255,255,255,0.4)", fontSize: "11px", fontFamily: "var(--font-mono)" }}>
                  {report.scan_id}
                </div>
              </div>
            )}

            {/* Divider */}
            <div style={{ height: "1px", background: "rgba(255,255,255,0.06)" }} />

            {/* Actions */}
            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              {/* PDF download placeholder */}
              {report.scan_id && (
                <a
                  href={`http://127.0.0.1:5000/scan/report/pdf/${report.scan_id}`}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display:       "block",
                    padding:       "12px 20px",
                    background:    `${gradeColor}18`,
                    border:        `1px solid ${gradeColor}44`,
                    borderRadius:  "8px",
                    color:         gradeColor,
                    fontFamily:    "var(--font-mono)",
                    fontSize:      "11px",
                    letterSpacing: "0.1em",
                    cursor:        "pointer",
                    textAlign:     "center",
                    textDecoration:"none",
                    fontWeight:    600,
                    boxShadow:     `0 0 14px ${gradeColor}18`,
                    transition:    "all 0.2s",
                  }}
                >
                  📄 DOWNLOAD PDF
                </a>
              )}

              <button
                onClick={onReset}
                style={{
                  padding:       "12px 20px",
                  background:    "transparent",
                  border:        "1px solid rgba(255,255,255,0.12)",
                  borderRadius:  "8px",
                  color:         "rgba(255,255,255,0.5)",
                  fontFamily:    "var(--font-mono)",
                  fontSize:      "11px",
                  letterSpacing: "0.1em",
                  cursor:        "pointer",
                  fontWeight:    600,
                  transition:    "all 0.2s",
                }}
                onMouseEnter={e => {
                  e.target.style.borderColor = "rgba(255,255,255,0.3)";
                  e.target.style.color = "rgba(255,255,255,0.8)";
                }}
                onMouseLeave={e => {
                  e.target.style.borderColor = "rgba(255,255,255,0.12)";
                  e.target.style.color = "rgba(255,255,255,0.5)";
                }}
              >
                ↩ NEW TARGET
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}


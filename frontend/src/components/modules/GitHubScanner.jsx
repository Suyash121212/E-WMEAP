// frontend/src/components/modules/GitHubScanner.jsx
// Module 4B — GitHub Repository Secret Scanner — Redesigned

import { useState } from "react";

// ── Severity config ───────────────────────────────────────────────────────────
const SEV = {
  Critical: { color: "#ff0040", bg: "rgba(255,0,64,0.08)",   border: "rgba(255,0,64,0.25)",   dot: "#ff0040" },
  High:     { color: "#ff6600", bg: "rgba(255,102,0,0.08)",  border: "rgba(255,102,0,0.25)",  dot: "#ff6600" },
  Medium:   { color: "#ffaa00", bg: "rgba(255,170,0,0.08)",  border: "rgba(255,170,0,0.25)",  dot: "#ffaa00" },
  Low:      { color: "#0080ff", bg: "rgba(0,128,255,0.08)",  border: "rgba(0,128,255,0.25)",  dot: "#0080ff" },
  None:     { color: "#00cc44", bg: "rgba(0,204,68,0.08)",   border: "rgba(0,204,68,0.2)",    dot: "#00cc44" },
};
const s = (sev) => SEV[sev] ?? SEV.Low;

// ── Shared primitives ─────────────────────────────────────────────────────────

function SevBadge({ sev }) {
  const c = s(sev);
  return (
    <span style={{
      display:       "inline-flex",
      alignItems:    "center",
      gap:           "5px",
      padding:       "3px 10px",
      borderRadius:  "20px",
      border:        `1px solid ${c.border}`,
      background:    c.bg,
      color:         c.color,
      fontSize:      "10px",
      fontWeight:    700,
      letterSpacing: "0.08em",
      fontFamily:    "var(--font-mono, monospace)",
      whiteSpace:    "nowrap",
    }}>
      <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: c.dot, flexShrink: 0 }} />
      {sev}
    </span>
  );
}

function StatCard({ label, value, sev }) {
  const c = sev ? s(sev) : null;
  return (
    <div style={{
      padding:      "24px 20px",
      background:   "rgba(255,255,255,0.02)",
      border:       "1px solid rgba(255,255,255,0.07)",
      borderRadius: "14px",
      textAlign:    "center",
    }}>
      <div style={{
        fontSize:   "36px",
        fontWeight: 900,
        fontFamily: "var(--font-mono, monospace)",
        color:      c ? c.color : "white",
        lineHeight: 1.1,
        textShadow: c ? `0 0 20px ${c.color}66` : "none",
        marginBottom: "8px",
      }}>
        {value}
      </div>
      <div style={{
        fontSize:      "10px",
        color:         "rgba(255,255,255,0.3)",
        letterSpacing: "0.18em",
        fontFamily:    "var(--font-mono, monospace)",
        textTransform: "uppercase",
      }}>
        {label}
      </div>
    </div>
  );
}

function SectionTitle({ dot, title, count }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
      <div style={{ width: "4px", height: "20px", borderRadius: "2px", background: dot, flexShrink: 0 }} />
      <h3 style={{
        fontSize:      "11px",
        fontWeight:    700,
        color:         "rgba(255,255,255,0.7)",
        letterSpacing: "0.2em",
        textTransform: "uppercase",
        fontFamily:    "var(--font-mono, monospace)",
        margin:        0,
      }}>
        {title}
      </h3>
      {count !== undefined && (
        <span style={{
          padding:      "2px 10px",
          background:   "rgba(255,255,255,0.06)",
          border:       "1px solid rgba(255,255,255,0.1)",
          borderRadius: "20px",
          fontSize:     "11px",
          color:        "rgba(255,255,255,0.4)",
          fontFamily:   "var(--font-mono, monospace)",
        }}>
          {count}
        </span>
      )}
    </div>
  );
}

function Divider() {
  return <div style={{ height: "1px", background: "rgba(255,255,255,0.05)", margin: "32px 0" }} />;
}

// ── Secret expand card ────────────────────────────────────────────────────────
function SecretCard({ secret, index }) {
  const [open, setOpen] = useState(false);
  const c = s(secret.severity);

  return (
    <div style={{
      borderRadius: "12px",
      border:       `1px solid ${open ? c.border : "rgba(255,255,255,0.06)"}`,
      background:   open ? c.bg : "rgba(255,255,255,0.02)",
      overflow:     "hidden",
      transition:   "all 0.2s ease",
      marginBottom: "10px",
    }}>
      {/* Row */}
      <div
        onClick={() => setOpen(!open)}
        style={{
          display:    "flex",
          alignItems: "center",
          gap:        "16px",
          padding:    "16px 20px",
          cursor:     "pointer",
        }}
      >
        {/* Number */}
        <span style={{
          color:       "rgba(255,255,255,0.15)",
          fontFamily:  "var(--font-mono, monospace)",
          fontSize:    "11px",
          fontWeight:  700,
          minWidth:    "28px",
          flexShrink:  0,
        }}>
          {String(index + 1).padStart(2, "0")}
        </span>

        {/* Dot */}
        <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: c.dot, flexShrink: 0, boxShadow: `0 0 8px ${c.dot}` }} />

        {/* Type */}
        <span style={{
          flex:        1,
          fontFamily:  "var(--font-mono, monospace)",
          fontSize:    "13px",
          fontWeight:  600,
          color:       "white",
          minWidth:    0,
        }}>
          {secret.type}
        </span>

        {/* File */}
        <span style={{
          fontFamily:  "var(--font-mono, monospace)",
          fontSize:    "11px",
          color:       "rgba(96,165,250,0.8)",
          maxWidth:    "220px",
          overflow:    "hidden",
          textOverflow:"ellipsis",
          whiteSpace:  "nowrap",
          flexShrink:  0,
        }}>
          {secret.file}
          {secret.line_number ? <span style={{ color: "rgba(255,255,255,0.2)" }}>:{secret.line_number}</span> : ""}
        </span>

        {/* Severity */}
        <div style={{ flexShrink: 0 }}>
          <SevBadge sev={secret.severity} />
        </div>

        {/* Arrow */}
        <span style={{
          color:      "rgba(255,255,255,0.2)",
          fontSize:   "12px",
          flexShrink: 0,
          transition: "transform 0.2s",
          transform:  open ? "rotate(180deg)" : "rotate(0deg)",
        }}>▾</span>
      </div>

      {/* Expanded */}
      {open && (
        <div style={{
          padding:    "0 20px 20px",
          borderTop:  "1px solid rgba(255,255,255,0.05)",
          paddingTop: "20px",
          display:    "flex",
          flexDirection: "column",
          gap:        "16px",
        }}>
          {/* Masked value */}
          <div>
            <div style={{ color: "rgba(255,255,255,0.3)", fontSize: "9px", letterSpacing: "0.2em", fontFamily: "monospace", marginBottom: "8px", textTransform: "uppercase" }}>
              Masked Value
            </div>
            <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: "8px", padding: "14px 16px", border: "1px solid rgba(255,255,255,0.05)" }}>
              <code style={{ color: "#00ff41", fontFamily: "monospace", fontSize: "12px", wordBreak: "break-all", lineHeight: 1.6 }}>
                {secret.snippet}
              </code>
            </div>
          </div>

          {/* Line context */}
          {secret.line_content && (
            <div>
              <div style={{ color: "rgba(255,255,255,0.3)", fontSize: "9px", letterSpacing: "0.2em", fontFamily: "monospace", marginBottom: "8px", textTransform: "uppercase" }}>
                Line Context
              </div>
              <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: "8px", padding: "14px 16px", border: "1px solid rgba(255,255,255,0.05)" }}>
                <code style={{ color: "#ffaa00", fontFamily: "monospace", fontSize: "12px", wordBreak: "break-all", lineHeight: 1.6 }}>
                  {secret.line_content}
                </code>
              </div>
            </div>
          )}

          {/* Action */}
          <div style={{ background: "rgba(0,180,80,0.06)", border: "1px solid rgba(0,180,80,0.15)", borderRadius: "8px", padding: "14px 16px" }}>
            <div style={{ color: "#00cc66", fontSize: "9px", letterSpacing: "0.2em", fontFamily: "monospace", marginBottom: "6px", textTransform: "uppercase", fontWeight: 700 }}>
              Immediate Action
            </div>
            <p style={{ color: "rgba(255,255,255,0.6)", fontSize: "12px", lineHeight: 1.6, margin: 0 }}>
              {_secretRecommendation(secret.type)}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Sensitive files ───────────────────────────────────────────────────────────
function SensitiveFilesSection({ files }) {
  if (!files?.length) return null;
  return (
    <div>
      <SectionTitle dot="#ffaa00" title="Sensitive Files in Repository" count={files.length} />
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {files.map((f, i) => {
          const c = s(f.severity);
          return (
            <div key={i} style={{
              display:      "flex",
              alignItems:   "center",
              gap:          "16px",
              padding:      "14px 20px",
              background:   c.bg,
              border:       `1px solid ${c.border}`,
              borderRadius: "10px",
            }}>
              <SevBadge sev={f.severity} />
              <a href={f.github_url} target="_blank" rel="noreferrer" style={{
                flex:          1,
                fontFamily:    "monospace",
                fontSize:      "12px",
                color:         "#60a5fa",
                textDecoration:"none",
                wordBreak:     "break-all",
              }}>
                {f.file}
              </a>
              <span style={{ color: "rgba(255,255,255,0.3)", fontSize: "11px", flexShrink: 0 }}>
                {f.description}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Suspicious commits ────────────────────────────────────────────────────────
function SuspiciousCommitsSection({ commits }) {
  if (!commits?.length) return null;
  return (
    <div>
      <SectionTitle dot="#a855f7" title="Suspicious Commit History" count={commits.length} />
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        {commits.map((c, i) => (
          <div key={i} style={{
            padding:      "18px 20px",
            background:   "rgba(168,85,247,0.05)",
            border:       "1px solid rgba(168,85,247,0.15)",
            borderRadius: "12px",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "10px" }}>
              <span style={{
                padding:      "3px 10px",
                background:   "rgba(168,85,247,0.15)",
                border:       "1px solid rgba(168,85,247,0.25)",
                borderRadius: "6px",
                color:        "#c084fc",
                fontFamily:   "monospace",
                fontSize:     "11px",
                fontWeight:   700,
              }}>
                {c.sha}
              </span>
              <span style={{ color: "rgba(255,255,255,0.3)", fontSize: "11px" }}>{c.date}</span>
            </div>
            <p style={{ color: "rgba(255,255,255,0.7)", fontSize: "13px", marginBottom: "8px", lineHeight: 1.5 }}>{c.message}</p>
            <p style={{ color: "#ffaa00", fontSize: "11px", marginBottom: "10px" }}>{c.note}</p>
            <a href={c.url} target="_blank" rel="noreferrer" style={{ color: "#60a5fa", fontSize: "11px", textDecoration: "none" }}>
              View commit ↗
            </a>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Files with secrets chips ──────────────────────────────────────────────────
function FilesWithSecrets({ files }) {
  if (!files?.length) return null;
  return (
    <div>
      <SectionTitle dot="#ff0040" title="Files Containing Secrets" count={files.length} />
      <div style={{ display: "flex", flexWrap: "wrap", gap: "10px" }}>
        {files.map((f, i) => (
          <a key={i} href={f.github_url} target="_blank" rel="noreferrer" style={{
            display:        "flex",
            alignItems:     "center",
            gap:            "10px",
            padding:        "10px 16px",
            background:     "rgba(255,0,64,0.06)",
            border:         "1px solid rgba(255,0,64,0.2)",
            borderRadius:   "10px",
            textDecoration: "none",
            transition:     "all 0.15s",
          }}
          onMouseEnter={e=>e.currentTarget.style.background="rgba(255,0,64,0.12)"}
          onMouseLeave={e=>e.currentTarget.style.background="rgba(255,0,64,0.06)"}
          >
            <span style={{ color: "#ff6680", fontFamily: "monospace", fontSize: "12px" }}>{f.path}</span>
            <span style={{ padding: "2px 8px", background: "rgba(255,0,64,0.2)", borderRadius: "6px", color: "#ff0040", fontSize: "10px", fontWeight: 700, whiteSpace: "nowrap" }}>
              {f.secrets_found} secret{f.secrets_found !== 1 ? "s" : ""}
            </span>
          </a>
        ))}
      </div>
    </div>
  );
}

// ── Loading skeleton ──────────────────────────────────────────────────────────
function LoadingSkeleton() {
  return (
    <div style={{ padding: "40px 0" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "32px" }}>
        <div style={{ width: "4px", height: "24px", borderRadius: "2px", background: "rgba(255,255,255,0.08)" }} />
        <div style={{ height: "14px", width: "200px", background: "rgba(255,255,255,0.06)", borderRadius: "6px" }} />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "16px", marginBottom: "32px" }}>
        {[...Array(5)].map((_, i) => (
          <div key={i} style={{ height: "90px", background: "rgba(255,255,255,0.03)", borderRadius: "14px", border: "1px solid rgba(255,255,255,0.05)" }} />
        ))}
      </div>
      <div style={{ height: "200px", background: "rgba(255,255,255,0.02)", borderRadius: "14px", border: "1px solid rgba(255,255,255,0.05)" }} />
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function GitHubScanner({ data, loading }) {
  const [sevFilter, setSevFilter] = useState("All");

  if (loading) return <LoadingSkeleton />;
  if (!data)   return null;

  if (data.error) {
    return (
      <div style={{ padding: "24px", background: "rgba(255,0,64,0.06)", border: "1px solid rgba(255,0,64,0.2)", borderRadius: "14px", color: "#ff6680", fontFamily: "monospace", fontSize: "13px" }}>
        ✕ {data.error}
      </div>
    );
  }

  const {
    repo_url, repo_info, secrets = [], sensitive_files = [],
    suspicious_commits = [], files_with_secrets = [],
    severity_counts = {}, overall_severity,
    total_files_in_repo, total_files_scanned, rate_limit_note,
  } = data;

  const ov = s(overall_severity);
  const visibleSecrets = sevFilter === "All" ? secrets : secrets.filter(sec => sec.severity === sevFilter);

  return (
    <section style={{ paddingBottom: "48px" }}>

      {/* ── Section header ── */}
      <div style={{ display: "flex", alignItems: "center", gap: "14px", marginBottom: "32px" }}>
        <div style={{ width: "4px", height: "28px", borderRadius: "2px", background: "#a855f7", boxShadow: "0 0 10px rgba(168,85,247,0.5)", flexShrink: 0 }} />
        <h2 style={{
          fontFamily:    "var(--font-mono, monospace)",
          fontSize:      "13px",
          fontWeight:    700,
          color:         "rgba(255,255,255,0.8)",
          letterSpacing: "0.2em",
          textTransform: "uppercase",
          margin:        0,
        }}>
          GitHub Repository Scanner
        </h2>
        {repo_url && (
          <a href={repo_url} target="_blank" rel="noreferrer" style={{
            marginLeft:     "auto",
            color:          "#60a5fa",
            fontSize:       "12px",
            fontFamily:     "monospace",
            textDecoration: "none",
            opacity:        0.7,
          }}>
            {repo_url.replace("https://github.com/", "")} ↗
          </a>
        )}
      </div>

      {/* ── Repo info card ── */}
      {repo_info && (
        <div style={{
          padding:      "24px 28px",
          background:   "rgba(255,255,255,0.02)",
          border:       "1px solid rgba(255,255,255,0.07)",
          borderRadius: "16px",
          marginBottom: "28px",
          display:      "flex",
          alignItems:   "flex-start",
          justifyContent:"space-between",
          gap:          "24px",
          flexWrap:     "wrap",
        }}>
          <div>
            <a href={`https://github.com/${repo_info.full_name}`} target="_blank" rel="noreferrer" style={{
              fontFamily:    "monospace",
              fontSize:      "16px",
              fontWeight:    700,
              color:         "#60a5fa",
              textDecoration:"none",
              display:       "block",
              marginBottom:  "8px",
            }}>
              {repo_info.full_name}
            </a>
            {repo_info.description && (
              <p style={{ color: "rgba(255,255,255,0.4)", fontSize: "13px", margin: 0, lineHeight: 1.5 }}>
                {repo_info.description}
              </p>
            )}
          </div>
          <div style={{ display: "flex", gap: "24px", flexShrink: 0 }}>
            {[
              { label: "Stars",    value: repo_info.stars,    icon: "⭐" },
              { label: "Forks",    value: repo_info.forks,    icon: "🍴" },
              { label: "Language", value: repo_info.language || "Unknown", icon: "📦" },
              { label: "Updated",  value: repo_info.updated_at, icon: "🗓" },
            ].map(m => (
              <div key={m.label} style={{ textAlign: "center" }}>
                <div style={{ fontSize: "18px", marginBottom: "4px" }}>{m.icon}</div>
                <div style={{ color: "white", fontSize: "13px", fontWeight: 600, marginBottom: "2px" }}>{m.value}</div>
                <div style={{ color: "rgba(255,255,255,0.25)", fontSize: "9px", letterSpacing: "0.15em", textTransform: "uppercase" }}>{m.label}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Rate limit warning ── */}
      {rate_limit_note && (
        <div style={{
          padding:      "14px 20px",
          background:   "rgba(255,170,0,0.06)",
          border:       "1px solid rgba(255,170,0,0.2)",
          borderRadius: "10px",
          color:        "#ffaa00",
          fontSize:     "12px",
          fontFamily:   "monospace",
          marginBottom: "28px",
        }}>
          ⚠ {rate_limit_note}
        </div>
      )}

      {/* ── Stat cards ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "16px", marginBottom: "40px" }}>
        <StatCard label="Overall Risk"   value={overall_severity}          sev={overall_severity} />
        <StatCard label="Secrets Found"  value={secrets.length}            sev={secrets.length > 0 ? "Critical" : "None"} />
        <StatCard label="Critical"       value={severity_counts.Critical ?? 0} sev="Critical" />
        <StatCard label="High"           value={severity_counts.High ?? 0}     sev="High" />
        <StatCard label="Files Scanned"  value={`${total_files_scanned}/${total_files_in_repo}`} />
      </div>

      {/* ── Clean state ── */}
      {secrets.length === 0 && sensitive_files.length === 0 && suspicious_commits.length === 0 ? (
        <div style={{
          padding:      "60px 40px",
          background:   "rgba(0,180,80,0.04)",
          border:       "1px solid rgba(0,180,80,0.15)",
          borderRadius: "16px",
          textAlign:    "center",
        }}>
          <div style={{ fontSize: "40px", marginBottom: "16px" }}>✓</div>
          <p style={{ color: "#00cc66", fontSize: "16px", fontWeight: 700, marginBottom: "8px" }}>
            No secrets detected
          </p>
          <p style={{ color: "rgba(255,255,255,0.3)", fontSize: "13px" }}>
            Scanned {total_files_scanned} files — no secret patterns found
          </p>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "40px" }}>

          {/* Files with secrets */}
          {files_with_secrets.length > 0 && <FilesWithSecrets files={files_with_secrets} />}

          {/* Sensitive files */}
          {sensitive_files.length > 0 && (
            <>
              <Divider />
              <SensitiveFilesSection files={sensitive_files} />
            </>
          )}

          {/* Suspicious commits */}
          {suspicious_commits.length > 0 && (
            <>
              <Divider />
              <SuspiciousCommitsSection commits={suspicious_commits} />
            </>
          )}

          {/* Secrets detail */}
          {secrets.length > 0 && (
            <>
              <Divider />
              <div>
                <SectionTitle dot="#ff0040" title="Secret Details" count={secrets.length} />

                {/* Severity filter pills */}
                <div style={{ display: "flex", gap: "8px", marginBottom: "24px", flexWrap: "wrap" }}>
                  {["All", "Critical", "High", "Medium", "Low"].map(f => {
                    const count = f === "All" ? secrets.length : secrets.filter(s => s.severity === f).length;
                    const isActive = sevFilter === f;
                    const c = f !== "All" ? s(f) : null;
                    return (
                      <button key={f} onClick={() => setSevFilter(f)} style={{
                        padding:      "8px 18px",
                        background:   isActive ? (c ? c.bg : "rgba(255,255,255,0.08)") : "rgba(255,255,255,0.02)",
                        border:       `1px solid ${isActive ? (c ? c.border : "rgba(255,255,255,0.2)") : "rgba(255,255,255,0.07)"}`,
                        borderRadius: "20px",
                        color:        isActive ? (c ? c.color : "white") : "rgba(255,255,255,0.35)",
                        fontFamily:   "monospace",
                        fontSize:     "11px",
                        fontWeight:   isActive ? 700 : 400,
                        cursor:       "pointer",
                        transition:   "all 0.15s",
                        display:      "flex",
                        alignItems:   "center",
                        gap:          "8px",
                      }}>
                        {f}
                        {count > 0 && (
                          <span style={{
                            padding:      "1px 7px",
                            background:   isActive ? (c ? `${c.color}25` : "rgba(255,255,255,0.1)") : "rgba(255,255,255,0.06)",
                            borderRadius: "10px",
                            fontSize:     "10px",
                            fontWeight:   700,
                          }}>
                            {count}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>

                {/* Secret cards */}
                <div>
                  {visibleSecrets.length === 0 ? (
                    <div style={{ padding: "40px", textAlign: "center", color: "rgba(255,255,255,0.2)", fontFamily: "monospace", fontSize: "12px" }}>
                      No {sevFilter} severity secrets
                    </div>
                  ) : (
                    visibleSecrets.map((secret, i) => (
                      <SecretCard key={i} secret={secret} index={i} />
                    ))
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </section>
  );
}

// ── Recommendation map ────────────────────────────────────────────────────────
function _secretRecommendation(type) {
  const map = {
    "AWS Access Key":    "Revoke immediately in AWS IAM Console. Audit CloudTrail for unauthorized usage.",
    "GitHub Token":      "Revoke at github.com/settings/tokens. Audit repository access logs.",
    "Google API Key":    "Revoke at console.cloud.google.com/apis/credentials. Check usage logs.",
    "Stripe Secret Key": "Revoke at dashboard.stripe.com/apikeys. Check for unauthorized charges.",
    "OpenAI API Key":    "Revoke at platform.openai.com/api-keys. Check usage for unexpected charges.",
    "Private RSA Key":   "Key is permanently compromised. Generate a new key pair immediately.",
    "Database URL":      "Rotate database password immediately. Check for unauthorized queries.",
    "Generic Password":  "Change this password immediately across all systems where it may be reused.",
    "JWT Token":         "Rotate the signing secret. All issued tokens are compromised.",
  };
  return map[type] ?? "Revoke or rotate this credential immediately. Remove from repository and add to .gitignore.";
}
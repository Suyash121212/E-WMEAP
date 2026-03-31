// frontend/src/components/modules/BusinessLogicScanner.jsx
// Module 5 — CORS, JWT & GraphQL Scanner

import { useState } from "react";
import { SeverityBadge, SEVERITY_STYLES } from "../ui/SeverityBadge";

// ── Tab system ────────────────────────────────────────────────────────────────

const TABS = [
  { id: "cors",    label: "CORS",    icon: "⇄",  color: "text-blue-400",   active: "bg-blue-900/40 border-blue-600/60 text-blue-300" },
  { id: "jwt",     label: "JWT",     icon: "🔐", color: "text-purple-400", active: "bg-purple-900/40 border-purple-600/60 text-purple-300" },
  { id: "graphql", label: "GraphQL", icon: "◈",  color: "text-pink-400",   active: "bg-pink-900/40 border-pink-600/60 text-pink-300" },
];

// ── Shared components ─────────────────────────────────────────────────────────

function SectionBadge({ count, severity }) {
  if (!count) return (
    <span className="text-[10px] text-emerald-400 font-semibold">✓ Clean</span>
  );
  const s = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.Info;
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${s.badge}`}>
      {count} issue{count !== 1 ? "s" : ""}
    </span>
  );
}

function TechniqueBox({ technique }) {
  if (!technique?.name) return null;
  return (
    <div className="mt-3 rounded-lg border border-orange-900/50 bg-orange-950/20 overflow-hidden">
      <div className="px-4 py-2 bg-orange-950/40 border-b border-orange-900/40 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest text-orange-400 font-semibold">
          ⚔ Exploitation Technique: {technique.name}
        </span>
      </div>
      <div className="p-4 space-y-3">
        {technique.steps?.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Attack Steps</p>
            <ol className="space-y-1.5">
              {technique.steps.map((step, i) => (
                <li key={i} className="flex gap-2 text-xs text-slate-300">
                  <span className="text-orange-500 font-mono font-bold flex-shrink-0 w-4">
                    {i + 1}.
                  </span>
                  {step}
                </li>
              ))}
            </ol>
          </div>
        )}
        {technique.sample_exploit && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1.5">Sample Exploit Query</p>
            <div className="bg-slate-900 rounded px-3 py-2 border border-slate-700/50">
              <code className="text-xs text-green-400 font-mono break-all">{technique.sample_exploit}</code>
            </div>
          </div>
        )}
        {technique.limitation && (
          <p className="text-[10px] text-slate-500 italic">⚠ Limitation: {technique.limitation}</p>
        )}
      </div>
    </div>
  );
}

function PocBox({ poc }) {
  const [copied, setCopied] = useState(false);
  if (!poc) return null;

  const copy = () => {
    navigator.clipboard.writeText(poc);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="mt-3 rounded-lg border border-purple-900/50 bg-purple-950/20 overflow-hidden">
      <div className="px-4 py-2 bg-purple-950/40 border-b border-purple-900/40 flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-widest text-purple-400 font-semibold">
          PoC — Working Exploit HTML
        </span>
        <button
          onClick={copy}
          className="text-[10px] text-purple-300 hover:text-white bg-purple-900/50 px-2 py-0.5 rounded transition-colors"
        >
          {copied ? "✓ Copied" : "Copy"}
        </button>
      </div>
      <div className="p-3 max-h-48 overflow-y-auto">
        <pre className="text-[11px] text-green-400 font-mono whitespace-pre-wrap break-all leading-relaxed">
          {poc}
        </pre>
      </div>
    </div>
  );
}

function FindingCard({ finding, accentColor }) {
  const [expanded, setExpanded] = useState(false);
  const s = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.Info;

  return (
    <div className={`border-b border-slate-700/30 last:border-0 ${
      finding.severity === "Critical" ? "border-l-2 border-l-red-500" :
      finding.severity === "High"     ? "border-l-2 border-l-orange-500" :
      finding.severity === "Medium"   ? "border-l-2 border-l-amber-500" :
      "border-l-2 border-l-slate-600"
    }`}>
      {/* Row */}
      <div
        className="flex items-center gap-3 px-4 py-3.5 cursor-pointer hover:bg-slate-700/20 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${s.dot}`} />
        <div className="flex-1 min-w-0">
          <p className="text-xs font-semibold text-slate-200 truncate">{finding.test}</p>
          {finding.endpoint && (
            <p className="text-[10px] text-slate-500 font-mono truncate mt-0.5">{finding.endpoint}</p>
          )}
        </div>
        {finding.exploitable && (
          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-900/50 text-red-300 border border-red-700/40 uppercase tracking-wider flex-shrink-0">
            Exploitable
          </span>
        )}
        <SeverityBadge level={finding.severity} />
        <span className={`text-slate-500 text-xs transition-transform flex-shrink-0 ${expanded ? "rotate-180" : ""}`}>▾</span>
      </div>

      {/* Expanded */}
      {expanded && (
        <div className="px-5 pb-5 pt-1 bg-slate-900/50 border-t border-slate-700/30 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Description</p>
              <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-red-400 mb-1">Impact</p>
              <p className="text-xs text-slate-300 leading-relaxed">{finding.impact}</p>
            </div>
          </div>

          {/* CORS specific */}
          {finding.received && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Received Header</p>
              <code className="text-xs text-amber-300 font-mono bg-slate-900 px-3 py-1.5 rounded block border border-slate-700/40">
                {finding.received}
              </code>
            </div>
          )}

          {/* JWT crafted token */}
          {finding.crafted_token && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Crafted Token (truncated)</p>
              <code className="text-xs text-green-400 font-mono bg-slate-900 px-3 py-1.5 rounded block border border-slate-700/40 break-all">
                {finding.crafted_token}
              </code>
            </div>
          )}

          {/* GraphQL sensitive fields */}
          {finding.sensitive_fields?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-red-400 mb-2">
                Sensitive Fields in Schema
              </p>
              <div className="flex flex-wrap gap-2">
                {finding.sensitive_fields.map((f, i) => (
                  <span key={i} className="font-mono text-xs px-2 py-0.5 bg-red-900/30 text-red-300 border border-red-800/40 rounded">
                    {f.type}.{f.field}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* GraphQL all types */}
          {finding.all_types?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
                All Schema Types ({finding.total_types})
              </p>
              <div className="flex flex-wrap gap-1.5 max-h-20 overflow-y-auto">
                {finding.all_types.map((t, i) => (
                  <span key={i} className={`font-mono text-[10px] px-2 py-0.5 rounded border ${
                    finding.sensitive_types?.includes(t)
                      ? "bg-red-900/30 text-red-300 border-red-800/40"
                      : "bg-slate-800 text-slate-400 border-slate-700/40"
                  }`}>
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Technique box */}
          <TechniqueBox technique={finding.technique} />

          {/* PoC HTML */}
          {finding.poc && <PocBox poc={finding.poc} />}

          {/* Recommendation */}
          <div className="bg-emerald-950/30 border border-emerald-900/40 rounded-lg px-3 py-2">
            <p className="text-[10px] uppercase tracking-widest text-emerald-400 font-semibold mb-1">Remediation</p>
            <p className="text-xs text-slate-300">{_remediation(finding.test)}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Sub-section renderers ─────────────────────────────────────────────────────

function CorsSection({ data }) {
  if (!data) return null;
  const { findings = [], endpoints_tested = [], no_cors_headers, summary } = data;

  return (
    <div className="space-y-4">
      {/* Meta */}
      <div className="flex flex-wrap gap-3 text-xs text-slate-500">
        <span>Endpoints tested: <span className="text-slate-300 font-mono">{endpoints_tested.length}</span></span>
        {no_cors_headers && (
          <span className="text-amber-400">⚠ No CORS headers detected on tested endpoints</span>
        )}
      </div>

      {/* Tested endpoints */}
      {endpoints_tested.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {endpoints_tested.map((ep, i) => (
            <span key={i} className="font-mono text-[10px] px-2 py-0.5 bg-slate-800 border border-slate-700/40 rounded text-slate-400">
              {ep.replace(/^https?:\/\/[^/]+/, "")}
            </span>
          ))}
        </div>
      )}

      {/* Summary */}
      <div className={`rounded-lg border px-4 py-2.5 text-xs ${
        findings.length > 0
          ? "bg-red-950/30 border-red-800/40 text-red-300"
          : "bg-emerald-950/30 border-emerald-800/40 text-emerald-300"
      }`}>
        {summary}
      </div>

      {/* Findings */}
      {findings.length > 0 ? (
        <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden">
          <div className="grid grid-cols-[1fr_auto_auto_auto] bg-slate-800/70 border-b border-slate-700/50 px-4 py-3">
            {["Test", "Endpoint", "Severity", ""].map((h, i) => (
              <div key={i} className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{h}</div>
            ))}
          </div>
          <div className="divide-y divide-slate-700/30">
            {findings.map((f, i) => <FindingCard key={i} finding={f} />)}
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-emerald-800/40 bg-emerald-950/20 px-5 py-8 text-center">
          <p className="text-emerald-400 text-sm font-semibold">✓ No CORS misconfigurations found</p>
        </div>
      )}
    </div>
  );
}

function JwtSection({ data }) {
  if (!data) return null;
  const { token_found, header, payload, algorithm, findings = [], summary } = data;

  return (
    <div className="space-y-4">
      {!token_found ? (
        <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 px-5 py-8 text-center">
          <p className="text-slate-400 text-sm">No JWT token auto-discovered</p>
          <p className="text-slate-600 text-xs mt-1">
            Provide a token manually using the JWT input field above to enable full testing.
          </p>
        </div>
      ) : (
        <>
          {/* Token info */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Algorithm</p>
              <p className="font-mono text-sm font-bold text-purple-400">{algorithm}</p>
            </div>
            {header && Object.entries(header).map(([k, v]) => (
              <div key={k} className="rounded-lg border border-slate-700/40 bg-slate-800/30 p-3">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">{k}</p>
                <p className="font-mono text-xs text-slate-300">{String(v)}</p>
              </div>
            ))}
          </div>

          {/* Payload claims */}
          {payload && Object.keys(payload).length > 0 && (
            <div className="rounded-lg border border-slate-700/40 bg-slate-800/20 overflow-hidden">
              <div className="px-4 py-2 bg-slate-800/60 border-b border-slate-700/40">
                <span className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold">JWT Payload Claims</span>
              </div>
              <div className="p-3 grid grid-cols-2 sm:grid-cols-3 gap-2">
                {Object.entries(payload).map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <span className="font-mono text-[10px] text-purple-400">{k}:</span>
                    <span className="font-mono text-[10px] text-slate-300 truncate">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Summary */}
          <div className={`rounded-lg border px-4 py-2.5 text-xs ${
            findings.some(f => f.exploitable)
              ? "bg-red-950/30 border-red-800/40 text-red-300"
              : "bg-emerald-950/30 border-emerald-800/40 text-emerald-300"
          }`}>
            {summary}
          </div>

          {/* Findings */}
          {findings.length > 0 && (
            <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden divide-y divide-slate-700/30">
              {findings.map((f, i) => <FindingCard key={i} finding={f} />)}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function GraphqlSection({ data }) {
  if (!data) return null;
  const { endpoint_found, endpoint, findings = [], summary } = data;

  return (
    <div className="space-y-4">
      {!endpoint_found ? (
        <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 px-5 py-8 text-center">
          <p className="text-slate-400 text-sm">No GraphQL endpoint found</p>
          <p className="text-slate-600 text-xs mt-1">Checked: /graphql, /api/graphql, /graphiql, /gql and more</p>
        </div>
      ) : (
        <>
          <div className="flex items-center gap-3">
            <span className="text-[10px] uppercase tracking-widest text-slate-500">Endpoint:</span>
            <span className="font-mono text-xs text-pink-400">{endpoint}</span>
          </div>

          <div className={`rounded-lg border px-4 py-2.5 text-xs ${
            findings.some(f => f.exploitable)
              ? "bg-red-950/30 border-red-800/40 text-red-300"
              : "bg-emerald-950/30 border-emerald-800/40 text-emerald-300"
          }`}>
            {summary}
          </div>

          {findings.length > 0 && (
            <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden divide-y divide-slate-700/30">
              {findings.map((f, i) => <FindingCard key={i} finding={f} />)}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Loading ───────────────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <section className="mb-10 animate-pulse">
      <div className="flex items-center gap-3 mb-5">
        <div className="w-1 h-6 rounded-full bg-slate-700" />
        <div className="h-4 w-64 bg-slate-700 rounded" />
      </div>
      <div className="flex gap-3 mb-6">
        {[1,2,3].map(i => <div key={i} className="h-10 w-28 bg-slate-800/50 rounded-lg border border-slate-700/40" />)}
      </div>
      <div className="h-64 bg-slate-800/20 rounded-xl border border-slate-700/40" />
    </section>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function BusinessLogicScanner({ data, loading }) {
  const [activeTab, setActiveTab] = useState("cors");

  if (loading) return <LoadingSkeleton />;
  if (!data)   return null;

  if (data.error) {
    return (
      <section className="mb-10">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-1 h-6 rounded-full bg-cyan-500" />
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">Business Logic Scanner</h2>
        </div>
        <div className="bg-red-950/30 border border-red-800/40 rounded-xl px-5 py-4 text-sm text-red-300">{data.error}</div>
      </section>
    );
  }

  const { cors, jwt, graphql, overall_severity, total_findings } = data;
  const s = SEVERITY_STYLES[overall_severity] ?? SEVERITY_STYLES.None;

  const tabCounts = {
    cors:    cors?.findings?.length ?? 0,
    jwt:     jwt?.findings?.length ?? 0,
    graphql: graphql?.findings?.length ?? 0,
  };

  const tabSeverities = {
    cors:    cors?.overall_severity,
    jwt:     jwt?.overall_severity,
    graphql: graphql?.overall_severity,
  };

  return (
    <section className="mb-10">
      {/* ── Header ── */}
      <div className="flex items-center gap-3 mb-5">
        <div className="w-1 h-6 rounded-full bg-cyan-500" />
        <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
          Business Logic Scanner
        </h2>
        <div className="ml-auto flex items-center gap-3">
          <span className={`text-xs font-bold ${s.text}`}>{overall_severity} Risk</span>
          <span className="text-xs text-slate-500">{total_findings} findings</span>
        </div>
      </div>

      {/* ── Tab bar ── */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {TABS.map(tab => {
          const isActive = activeTab === tab.id;
          const count    = tabCounts[tab.id];
          const sev      = tabSeverities[tab.id];
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border text-xs font-semibold transition-all ${
                isActive ? tab.active : "bg-slate-800/40 border-slate-700/40 text-slate-400 hover:border-slate-500"
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
              <SectionBadge count={count} severity={sev} />
            </button>
          );
        })}
      </div>

      {/* ── Tab content ── */}
      <div>
        {activeTab === "cors"    && <CorsSection    data={cors} />}
        {activeTab === "jwt"     && <JwtSection     data={jwt} />}
        {activeTab === "graphql" && <GraphqlSection data={graphql} />}
      </div>
    </section>
  );
}

// ── Remediation map ───────────────────────────────────────────────────────────

function _remediation(testName) {
  const map = {
    "Wildcard Origin":               "Remove wildcard CORS. Maintain an explicit allowlist of trusted origins.",
    "Origin Reflection":             "Never reflect the Origin header back. Use a strict server-side allowlist.",
    "Null Origin Allowed":           "Never allow null origin in production. It is only valid for sandboxed contexts you control.",
    "Credentials + Origin Reflection":"This is the most dangerous CORS config. Immediately restrict to explicit trusted origins only.",
    "Subdomain Trust":               "Avoid trusting entire subdomain patterns. Allowlist specific subdomains explicitly.",
    "Algorithm Confusion (alg: none)":"Reject any JWT with alg:none. Hardcode the expected algorithm server-side.",
    "Weak HMAC Secret":              "Use a cryptographically random secret of at least 256 bits. Never use dictionary words.",
    "Expired Token Accepted":        "Always validate the exp claim. Reject tokens past their expiry time.",
    "Payload Tampering Accepted":    "Verify signature before trusting any payload claims. Use a well-tested JWT library.",
    "Invalid JWT Accepted":          "JWT validation appears disabled. Enable strict signature verification immediately.",
    "RS256 Algorithm Detected":      "Disable algorithm switching. Accept only RS256. Do not accept HS256 fallback.",
    "GraphQL Introspection Enabled": "Disable introspection in production: set introspection: false in your GraphQL server config.",
    "Query Batching Enabled":        "Implement query depth limits and per-IP rate limiting at the operation level, not HTTP level.",
    "Field Suggestions Enabled":     "Disable field suggestions in production to prevent schema enumeration.",
    "Unauthenticated Data Access":   "All GraphQL resolvers must check authentication before returning data.",
  };
  return map[testName] ?? "Review and restrict this configuration. Follow the principle of least privilege.";
}

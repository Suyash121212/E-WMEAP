// frontend/src/components/modules/DirectoryScanner.jsx
// Module 4 — Directory & Endpoint Discovery + PoC Generation

import { useState } from "react";
import { SeverityBadge, StatusBadge, SEVERITY_STYLES } from "../ui/SeverityBadge";

// ── Category meta ─────────────────────────────────────────────────────────────
const CATEGORY_META = {
  source_control: { label: "Source Control", icon: "⎇",  color: "text-red-400",    bg: "bg-red-900/20 border-red-800/40" },
  secrets:        { label: "Secrets / Config", icon: "🔑", color: "text-red-400",    bg: "bg-red-900/20 border-red-800/40" },
  admin:          { label: "Admin Panels",    icon: "⚙",  color: "text-orange-400", bg: "bg-orange-900/20 border-orange-800/40" },
  backup:         { label: "Backup / Dumps",  icon: "🗄",  color: "text-orange-400", bg: "bg-orange-900/20 border-orange-800/40" },
  api:            { label: "API Endpoints",   icon: "◈",  color: "text-blue-400",   bg: "bg-blue-900/20 border-blue-800/40" },
  server_info:    { label: "Server Info",     icon: "⬡",  color: "text-amber-400",  bg: "bg-amber-900/20 border-amber-800/40" },
  metadata:       { label: "Metadata",        icon: "◎",  color: "text-slate-400",  bg: "bg-slate-800/40 border-slate-700/40" },
  logs:           { label: "Log Files",       icon: "📋", color: "text-amber-400",  bg: "bg-amber-900/20 border-amber-800/40" },
};

const STATUS_COLOR = {
  200: "text-red-400 bg-red-900/30 border-red-700/40",
  403: "text-amber-400 bg-amber-900/30 border-amber-700/40",
  301: "text-blue-400 bg-blue-900/30 border-blue-700/40",
  302: "text-blue-400 bg-blue-900/30 border-blue-700/40",
  401: "text-purple-400 bg-purple-900/30 border-purple-700/40",
};

// ── Sub-components ────────────────────────────────────────────────────────────

function SummaryBar({ data }) {
  const { total_found, total_paths_checked, overall_severity, severity_counts, category_counts } = data;
  const s = SEVERITY_STYLES[overall_severity] ?? SEVERITY_STYLES.Info;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
      {/* Overall risk */}
      <div className={`col-span-2 sm:col-span-1 rounded-xl border p-4 ${
        overall_severity === "Critical" ? "bg-red-950/40 border-red-800/50" :
        overall_severity === "High"     ? "bg-red-900/30 border-red-700/40" :
        overall_severity === "Medium"   ? "bg-amber-900/30 border-amber-700/40" :
        "bg-slate-800/40 border-slate-700/40"
      }`}>
        <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Overall Risk</p>
        <p className={`text-2xl font-black ${s.text}`}>{overall_severity}</p>
        <p className="text-xs text-slate-500 mt-1">{total_found} / {total_paths_checked} paths found</p>
      </div>

      {/* Severity breakdown */}
      {["Critical","High","Medium","Low"].map(sev => (
        <div key={sev} className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-4">
          <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">{sev}</p>
          <p className={`text-2xl font-black ${SEVERITY_STYLES[sev]?.text ?? "text-slate-400"}`}>
            {severity_counts?.[sev] ?? 0}
          </p>
        </div>
      ))}
    </div>
  );
}

function CategoryChips({ findings, activeCategory, onSelect }) {
  const cats = [...new Set(findings.map(f => f.category))];
  return (
    <div className="flex flex-wrap gap-2 mb-5">
      <button
        onClick={() => onSelect(null)}
        className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
          activeCategory === null
            ? "bg-blue-600 border-blue-500 text-white"
            : "bg-slate-800/40 border-slate-700/40 text-slate-400 hover:border-slate-500"
        }`}
      >
        All ({findings.length})
      </button>
      {cats.map(cat => {
        const meta = CATEGORY_META[cat] ?? { label: cat, icon: "•", color: "text-slate-400", bg: "" };
        const count = findings.filter(f => f.category === cat).length;
        return (
          <button
            key={cat}
            onClick={() => onSelect(cat)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
              activeCategory === cat
                ? `border-slate-500 bg-slate-700 text-white`
                : `bg-slate-800/40 border-slate-700/40 ${meta.color} hover:border-slate-500`
            }`}
          >
            {meta.icon} {meta.label} ({count})
          </button>
        );
      })}
    </div>
  );
}

// ── PoC renderers ─────────────────────────────────────────────────────────────

function GitPoc({ data }) {
  if (!data) return null;
  const { reconstructed, files_found, secrets, error, tool } = data;

  return (
    <div className="mt-3 rounded-lg border border-red-900/50 bg-red-950/20 overflow-hidden">
      <div className="px-4 py-2 bg-red-950/40 border-b border-red-900/40 flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-widest text-red-400 font-semibold">
          PoC: Git Repository Reconstruction
        </span>
        <span className="text-[10px] text-slate-500">{tool}</span>
      </div>
      <div className="p-4 space-y-4">
        {error ? (
          <div className="text-xs text-amber-300 bg-amber-900/20 border border-amber-800/40 rounded px-3 py-2">
            ⚠ {error}
          </div>
        ) : reconstructed ? (
          <>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-emerald-400 font-semibold mb-2">
                ✓ Source Code Reconstructed — {files_found?.length ?? 0} files dumped
              </p>
              <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                {files_found?.map((f, i) => (
                  <span key={i} className="font-mono text-[10px] px-2 py-0.5 bg-slate-900 border border-slate-700 rounded text-slate-400">
                    {f}
                  </span>
                ))}
              </div>
            </div>
            {secrets?.length > 0 ? (
              <div>
                <p className="text-[10px] uppercase tracking-widest text-red-400 font-semibold mb-2">
                  🚨 {secrets.length} Secret(s) Found in Dumped Code
                </p>
                <div className="space-y-2">
                  {secrets.map((s, i) => (
                    <div key={i} className="bg-slate-900 rounded-lg px-3 py-2 border border-slate-700/50">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[10px] font-bold text-red-300 uppercase">{s.type}</span>
                        <span className="text-[10px] text-slate-500 font-mono">{s.file}</span>
                      </div>
                      <code className="text-xs text-green-400 font-mono break-all">{s.snippet}</code>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500">No secrets detected in reconstructed code.</p>
            )}
          </>
        ) : (
          <p className="text-xs text-slate-400">
            .git directory found but reconstruction was not attempted automatically.
            Install git-dumper to enable: <code className="text-green-400">pip install git-dumper</code>
          </p>
        )}
      </div>
    </div>
  );
}

function EnvPoc({ data }) {
  if (!data) return null;
  const { keys_found, sensitive_keys, total_keys } = data;

  return (
    <div className="mt-3 rounded-lg border border-red-900/50 bg-red-950/20 overflow-hidden">
      <div className="px-4 py-2 bg-red-950/40 border-b border-red-900/40">
        <span className="text-[10px] uppercase tracking-widest text-red-400 font-semibold">
          PoC: Environment File Contents
        </span>
      </div>
      <div className="p-4 space-y-3">
        <p className="text-xs text-slate-300">
          {total_keys} environment variable(s) exposed. Values masked for safety.
        </p>
        {sensitive_keys?.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-red-400 font-semibold mb-2">
              🔑 Sensitive Keys Detected
            </p>
            <div className="space-y-1.5">
              {sensitive_keys.map((k, i) => (
                <div key={i} className="flex items-center gap-3 bg-slate-900 rounded px-3 py-1.5 border border-slate-700/40">
                  <span className="font-mono text-xs text-amber-300">{k.key}</span>
                  <span className="text-slate-600">=</span>
                  <code className="font-mono text-xs text-red-300">{k.masked_value}</code>
                </div>
              ))}
            </div>
          </div>
        )}
        {keys_found?.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-1.5">
              All Keys Found
            </p>
            <div className="flex flex-wrap gap-1.5">
              {keys_found.map((k, i) => (
                <span key={i} className="font-mono text-[10px] px-2 py-0.5 bg-slate-800 border border-slate-700/40 rounded text-slate-400">
                  {k}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function GraphQLPoc({ data }) {
  if (!data) return null;
  const { introspection_enabled, types_found, sensitive_types } = data;

  if (!introspection_enabled) {
    return (
      <div className="mt-3 rounded-lg border border-slate-700/40 bg-slate-800/20 px-4 py-3">
        <p className="text-xs text-slate-400">GraphQL introspection is disabled — schema is protected.</p>
      </div>
    );
  }

  return (
    <div className="mt-3 rounded-lg border border-purple-900/50 bg-purple-950/20 overflow-hidden">
      <div className="px-4 py-2 bg-purple-950/40 border-b border-purple-900/40">
        <span className="text-[10px] uppercase tracking-widest text-purple-400 font-semibold">
          PoC: GraphQL Introspection Enabled — Schema Exposed
        </span>
      </div>
      <div className="p-4 space-y-3">
        {sensitive_types?.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-red-400 font-semibold mb-2">
              ⚠ Sensitive Types in Schema
            </p>
            <div className="flex flex-wrap gap-1.5">
              {sensitive_types.map((t, i) => (
                <span key={i} className="font-mono text-xs px-2 py-0.5 bg-red-900/40 text-red-300 border border-red-800/40 rounded">
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}
        <div>
          <p className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-1.5">
            All Types Found ({types_found?.length})
          </p>
          <div className="flex flex-wrap gap-1.5 max-h-20 overflow-y-auto">
            {types_found?.map((t, i) => (
              <span key={i} className="font-mono text-[10px] px-2 py-0.5 bg-slate-800 border border-slate-700/40 rounded text-slate-400">
                {t}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function RobotsPoc({ data }) {
  if (!data?.hidden_paths?.length) return null;
  return (
    <div className="mt-3 rounded-lg border border-amber-900/50 bg-amber-950/20 overflow-hidden">
      <div className="px-4 py-2 bg-amber-950/40 border-b border-amber-900/40">
        <span className="text-[10px] uppercase tracking-widest text-amber-400 font-semibold">
          Hidden Paths from robots.txt
        </span>
      </div>
      <div className="p-4 flex flex-wrap gap-2">
        {data.hidden_paths.map((p, i) => (
          <span key={i} className="font-mono text-xs px-2 py-0.5 bg-slate-900 text-amber-300 border border-amber-800/40 rounded">
            {p}
          </span>
        ))}
      </div>
    </div>
  );
}

function PocRenderer({ poc }) {
  if (!poc) return null;
  if (poc.type === "git_reconstruction")   return <GitPoc     data={poc.data} />;
  if (poc.type === "env_parse")            return <EnvPoc     data={poc.data} />;
  if (poc.type === "graphql_introspection")return <GraphQLPoc data={poc.data} />;
  if (poc.type === "robots_hidden_paths")  return <RobotsPoc  data={poc.data} />;
  return null;
}

// ── Finding row ───────────────────────────────────────────────────────────────

function FindingRow({ finding, index }) {
  const [expanded, setExpanded] = useState(false);
  const meta = CATEGORY_META[finding.category] ?? { label: finding.category, icon: "•", color: "text-slate-400" };
  const statusCls = STATUS_COLOR[finding.status_code] ?? "text-slate-400 bg-slate-800/40 border-slate-600/40";
  const s = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.Info;
  const hasPoc = !!finding.poc;

  return (
    <div>
      <div
        onClick={() => setExpanded(!expanded)}
        className={`grid grid-cols-[2fr_1fr_1fr_1fr_auto] gap-0 cursor-pointer
          hover:bg-slate-700/20 transition-colors items-center
          ${expanded ? "bg-slate-700/20" : ""}
          ${finding.severity === "Critical" ? "border-l-2 border-red-500" :
            finding.severity === "High"     ? "border-l-2 border-orange-500" :
            finding.severity === "Medium"   ? "border-l-2 border-amber-500" :
            "border-l-2 border-transparent"}
        `}
      >
        {/* Path */}
        <div className="px-4 py-3 flex items-center gap-2 min-w-0">
          <span className={`text-sm flex-shrink-0 ${meta.color}`}>{meta.icon}</span>
          <span className="font-mono text-xs text-slate-200 truncate">{finding.path}</span>
          {hasPoc && (
            <span className="flex-shrink-0 text-[9px] font-bold px-1.5 py-0.5 rounded bg-purple-900/50 text-purple-300 border border-purple-700/40 uppercase tracking-wider">
              PoC
            </span>
          )}
        </div>

        {/* Category */}
        <div className="px-3 py-3 hidden sm:block">
          <span className={`text-[10px] font-semibold uppercase tracking-wider ${meta.color}`}>
            {meta.label}
          </span>
        </div>

        {/* HTTP Status */}
        <div className="px-3 py-3">
          <span className={`font-mono text-xs font-bold px-2 py-0.5 rounded border ${statusCls}`}>
            {finding.status_code}
          </span>
        </div>

        {/* Severity */}
        <div className="px-3 py-3">
          <SeverityBadge level={finding.severity} />
        </div>

        {/* Expand arrow */}
        <div className="px-3 py-3">
          <span className={`text-slate-500 text-xs transition-transform inline-block ${expanded ? "rotate-180" : ""}`}>▾</span>
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-5 pb-5 pt-2 bg-slate-900/60 border-t border-slate-700/30">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-3">
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Full URL</p>
              <a
                href={finding.full_url}
                target="_blank"
                rel="noreferrer"
                className="font-mono text-xs text-blue-400 hover:text-blue-300 underline underline-offset-2 break-all"
              >
                {finding.full_url}
              </a>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Description</p>
              <p className="text-xs text-slate-300">{finding.description}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Response</p>
              <p className="text-xs text-slate-300">
                HTTP {finding.status_code} — {finding.status_label}
                {finding.content_length > 0 && ` · ${finding.content_length} bytes`}
              </p>
            </div>
            {finding.redirect_to && (
              <div>
                <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Redirects To</p>
                <p className="font-mono text-xs text-blue-400">{finding.redirect_to}</p>
              </div>
            )}
          </div>

          {/* Recommendation */}
          <div className="mb-3 bg-emerald-950/30 border border-emerald-900/40 rounded-lg px-3 py-2">
            <p className="text-[10px] uppercase tracking-widest text-emerald-400 font-semibold mb-1">Recommendation</p>
            <p className="text-xs text-slate-300">{_recommendation(finding)}</p>
          </div>

          {/* PoC block */}
          <PocRenderer poc={finding.poc} />
        </div>
      )}
    </div>
  );
}

function _recommendation(finding) {
  const recs = {
    source_control: "Remove the .git directory from your web root. Add it to .gitignore or configure your web server to deny access to /.git/.",
    secrets:        "Immediately rotate all credentials found in this file. Remove the file from public web access. Store secrets in environment variables or a vault.",
    admin:          "Restrict admin panel access by IP whitelist. Ensure strong authentication with MFA is enforced.",
    backup:         "Remove backup files from the web root. Store backups in a non-public directory or off-site storage.",
    api:            "Audit exposed API endpoints. Ensure all endpoints require authentication. Disable introspection in production.",
    server_info:    "Disable server status pages and PHP info files in production server configuration.",
    metadata:       "Review what information is exposed. Restrict access to sensitive metadata files via server config.",
    logs:           "Move log files outside the web root. Never expose application logs to the internet.",
  };
  return recs[finding.category] ?? "Restrict access to this path via server configuration.";
}

// ── Loading skeleton ──────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <section className="mb-10 animate-pulse">
      <div className="flex items-center gap-3 mb-5">
        <div className="w-1 h-6 rounded-full bg-slate-700" />
        <div className="h-4 w-56 bg-slate-700 rounded" />
      </div>
      <div className="grid grid-cols-4 gap-3 mb-6">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-20 bg-slate-800/50 rounded-xl border border-slate-700/40" />
        ))}
      </div>
      <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 overflow-hidden">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex gap-4 px-4 py-3 border-b border-slate-700/30">
            <div className="h-3 w-48 bg-slate-700 rounded" />
            <div className="h-3 w-20 bg-slate-700 rounded ml-auto" />
            <div className="h-3 w-12 bg-slate-700 rounded" />
          </div>
        ))}
      </div>
    </section>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function DirectoryScanner({ data, loading }) {
  const [activeCategory, setActiveCategory] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("All");

  if (loading) return <LoadingSkeleton />;
  if (!data)   return null;

  if (data.error) {
    return (
      <section className="mb-10">
        <div className="flex items-center gap-3 mb-5">
          <div className="w-1 h-6 rounded-full bg-orange-500" />
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">Directory Discovery</h2>
        </div>
        <div className="bg-red-950/30 border border-red-800/40 rounded-xl px-5 py-4 text-sm text-red-300">
          {data.error}
        </div>
      </section>
    );
  }

  const { findings = [], risk_summary, total_paths_checked, total_found } = data;

  // Apply filters
  let visible = findings;
  if (activeCategory) visible = visible.filter(f => f.category === activeCategory);
  if (severityFilter !== "All") visible = visible.filter(f => f.severity === severityFilter);

  return (
    <section className="mb-10">
      {/* ── Section header ── */}
      <div className="flex items-center gap-3 mb-5">
        <div className="w-1 h-6 rounded-full bg-orange-500" />
        <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
          Directory & Endpoint Discovery
        </h2>
        <span className="ml-auto text-xs text-slate-500 tabular-nums">
          {total_paths_checked} paths checked
        </span>
      </div>

      {/* ── Summary cards ── */}
      <SummaryBar data={data} />

      {/* ── Risk summary bar ── */}
      <div className={`rounded-xl border px-4 py-3 mb-5 text-xs font-medium ${
        data.overall_severity === "Critical" ? "bg-red-950/40 border-red-800/50 text-red-300" :
        data.overall_severity === "High"     ? "bg-orange-950/40 border-orange-800/50 text-orange-300" :
        data.overall_severity === "Medium"   ? "bg-amber-950/40 border-amber-800/50 text-amber-300" :
        data.overall_severity === "None"     ? "bg-emerald-950/40 border-emerald-800/50 text-emerald-300" :
        "bg-slate-800/40 border-slate-700/40 text-slate-400"
      }`}>
        {risk_summary}
      </div>

      {findings.length === 0 ? (
        <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 px-5 py-12 text-center">
          <p className="text-slate-500 text-sm">No sensitive paths or directories found.</p>
          <p className="text-slate-600 text-xs mt-1">
            All {total_paths_checked} checked paths returned 404.
          </p>
        </div>
      ) : (
        <>
          {/* ── Category filter chips ── */}
          <CategoryChips
            findings={findings}
            activeCategory={activeCategory}
            onSelect={setActiveCategory}
          />

          {/* ── Severity filter tabs ── */}
          <div className="flex gap-2 mb-4">
            {["All", "Critical", "High", "Medium", "Low"].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1 rounded-lg text-xs font-semibold border transition-all ${
                  severityFilter === sev
                    ? "bg-slate-600 border-slate-500 text-white"
                    : "bg-transparent border-slate-700/40 text-slate-500 hover:text-slate-300"
                }`}
              >
                {sev}
                {sev !== "All" && (
                  <span className="ml-1 opacity-60">
                    ({findings.filter(f => f.severity === sev).length})
                  </span>
                )}
              </button>
            ))}
            <span className="ml-auto text-xs text-slate-500 self-center">
              Showing {visible.length} of {findings.length}
            </span>
          </div>

          {/* ── Findings table ── */}
          <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden">
            {/* Table header */}
            <div className="grid grid-cols-[2fr_1fr_1fr_1fr_auto] gap-0 bg-slate-800/70 border-b border-slate-700/50">
              {["Path", "Category", "Status", "Severity", ""].map((h, i) => (
                <div key={i} className={`px-4 py-3 text-[10px] font-semibold uppercase tracking-widest text-slate-500 ${i === 1 ? "hidden sm:block" : ""}`}>
                  {h}
                </div>
              ))}
            </div>

            {/* Rows */}
            <div className="divide-y divide-slate-700/30">
              {visible.length === 0 ? (
                <div className="px-5 py-8 text-center text-sm text-slate-500">
                  No findings match the selected filters.
                </div>
              ) : (
                visible.map((finding, i) => (
                  <FindingRow key={i} finding={finding} index={i} />
                ))
              )}
            </div>
          </div>
        </>
      )}
    </section>
  );
}
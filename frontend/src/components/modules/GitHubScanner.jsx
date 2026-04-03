// frontend/src/components/modules/GitHubScanner.jsx
// Module 4B — GitHub Repository Secret Scanner

import { useState } from "react";
import { SeverityBadge, SEVERITY_STYLES } from "../ui/SeverityBadge";

// ── Helpers ───────────────────────────────────────────────────────────────────

function StatCard({ label, value, color = "text-slate-200" }) {
  return (
    <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-4">
      <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">{label}</p>
      <p className={`text-2xl font-black font-mono ${color}`}>{value}</p>
    </div>
  );
}

function RepoInfoCard({ info }) {
  return (
    <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 p-4 mb-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <a
            href={`https://github.com/${info.full_name}`}
            target="_blank"
            rel="noreferrer"
            className="font-mono font-bold text-blue-400 hover:text-blue-300 text-sm underline underline-offset-2"
          >
            {info.full_name}
          </a>
          {info.description && (
            <p className="text-xs text-slate-400 mt-1">{info.description}</p>
          )}
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>⭐ {info.stars}</span>
          <span>🍴 {info.forks}</span>
          <span>📦 {info.language ?? "Unknown"}</span>
          <span>🗓 {info.updated_at}</span>
        </div>
      </div>
    </div>
  );
}

function SecretCard({ secret, index }) {
  const [expanded, setExpanded] = useState(false);
  const s = SEVERITY_STYLES[secret.severity] ?? SEVERITY_STYLES.Info;

  return (
    <div
      className={`border-b border-slate-700/30 last:border-0
        ${secret.severity === "Critical" ? "border-l-2 border-l-red-500" :
          secret.severity === "High"     ? "border-l-2 border-l-orange-500" :
          "border-l-2 border-l-amber-500"}
      `}
    >
      <div
        className="grid grid-cols-[auto_2fr_1.5fr_1fr_auto] gap-0 px-4 py-3
          cursor-pointer hover:bg-slate-700/20 transition-colors items-center"
        onClick={() => setExpanded(!expanded)}
      >
        {/* Index */}
        <div className="pr-3 text-slate-600 font-mono text-xs w-8">
          {String(index + 1).padStart(2, "0")}
        </div>

        {/* Type */}
        <div className="font-mono text-xs text-slate-200 font-semibold truncate pr-3">
          {secret.type}
        </div>

        {/* File */}
        <div className="font-mono text-[11px] text-blue-400 truncate pr-3">
          {secret.file}
          {secret.line_number && (
            <span className="text-slate-600">:{secret.line_number}</span>
          )}
        </div>

        {/* Severity */}
        <div>
          <SeverityBadge level={secret.severity} />
        </div>

        {/* Arrow */}
        <div className="pl-3">
          <span className={`text-slate-500 text-xs transition-transform inline-block ${expanded ? "rotate-180" : ""}`}>
            ▾
          </span>
        </div>
      </div>

      {expanded && (
        <div className="px-5 pb-4 pt-1 bg-slate-900/50 border-t border-slate-700/30">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-3">
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Secret Type</p>
              <p className="text-xs text-slate-200">{secret.type}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">File</p>
              <p className="font-mono text-xs text-blue-400">
                {secret.file}
                {secret.line_number ? ` (line ${secret.line_number})` : ""}
              </p>
            </div>
          </div>

          {/* Masked snippet */}
          <div className="mb-3">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1.5">
              Masked Value
            </p>
            <div className="bg-slate-900 rounded-lg px-3 py-2 border border-slate-700/50">
              <code className="text-xs text-green-400 font-mono break-all">
                {secret.snippet}
              </code>
            </div>
          </div>

          {/* Line context */}
          {secret.line_content && (
            <div className="mb-3">
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1.5">
                Line Context (masked)
              </p>
              <div className="bg-slate-900 rounded-lg px-3 py-2 border border-slate-700/50">
                <code className="text-xs text-amber-300 font-mono break-all">
                  {secret.line_content}
                </code>
              </div>
            </div>
          )}

          {/* Recommendation */}
          <div className="bg-emerald-950/30 border border-emerald-900/40 rounded-lg px-3 py-2">
            <p className="text-[10px] uppercase tracking-widest text-emerald-400 font-semibold mb-1">
              Immediate Action Required
            </p>
            <p className="text-xs text-slate-300">
              {_secretRecommendation(secret.type)}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function SensitiveFilesSection({ files }) {
  if (!files?.length) return null;
  return (
    <div className="mb-6">
      <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest mb-3 flex items-center gap-2">
        <span className="w-1 h-4 rounded-full bg-amber-500 inline-block" />
        Sensitive Files Detected in Repository ({files.length})
      </h3>
      <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden divide-y divide-slate-700/30">
        {files.map((f, i) => (
          <div key={i} className="flex items-center gap-4 px-4 py-3 hover:bg-slate-700/20 transition-colors">
            <span className={`text-xs font-bold ${SEVERITY_STYLES[f.severity]?.text ?? "text-slate-400"}`}>
              {f.severity}
            </span>
            <a
              href={f.github_url}
              target="_blank"
              rel="noreferrer"
              className="font-mono text-xs text-blue-400 hover:text-blue-300 underline underline-offset-2 flex-1"
            >
              {f.file}
            </a>
            <span className="text-xs text-slate-500 hidden sm:block">{f.description}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SuspiciousCommitsSection({ commits }) {
  if (!commits?.length) return null;
  return (
    <div className="mb-6">
      <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest mb-3 flex items-center gap-2">
        <span className="w-1 h-4 rounded-full bg-purple-500 inline-block" />
        Suspicious Commit History ({commits.length})
      </h3>
      <div className="rounded-xl border border-purple-900/40 bg-purple-950/20 overflow-hidden divide-y divide-purple-900/30">
        {commits.map((c, i) => (
          <div key={i} className="px-4 py-3">
            <div className="flex items-center gap-3 mb-1">
              <span className="font-mono text-[10px] text-purple-400 bg-purple-900/40 px-2 py-0.5 rounded">
                {c.sha}
              </span>
              <span className="text-[10px] text-slate-500">{c.date}</span>
            </div>
            <p className="text-xs text-slate-300 mb-1">{c.message}</p>
            <p className="text-[10px] text-amber-400">{c.note}</p>
            <a
              href={c.url}
              target="_blank"
              rel="noreferrer"
              className="text-[10px] text-blue-400 hover:text-blue-300 underline underline-offset-2"
            >
              View commit ↗
            </a>
          </div>
        ))}
      </div>
    </div>
  );
}

function FilesScannedSection({ files }) {
  if (!files?.length) return null;
  return (
    <div className="mb-6">
      <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest mb-3 flex items-center gap-2">
        <span className="w-1 h-4 rounded-full bg-red-500 inline-block" />
        Files Containing Secrets ({files.length})
      </h3>
      <div className="flex flex-wrap gap-2">
        {files.map((f, i) => (
          <a
            key={i}
            href={f.github_url}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 px-3 py-1.5 bg-red-950/30 border border-red-800/40 rounded-lg
              text-xs font-mono text-red-300 hover:text-red-200 hover:bg-red-950/50 transition-colors"
          >
            {f.path}
            <span className="bg-red-800/50 px-1.5 py-0.5 rounded text-[10px]">
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
      <div className="rounded-xl border border-slate-700/40 h-48 bg-slate-800/20" />
    </section>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function GitHubScanner({ data, loading }) {
  const [secretFilter, setSecretFilter] = useState("All");

  if (loading) return <LoadingSkeleton />;
  if (!data)   return null;

  if (data.error) {
    return (
      <section className="mb-10">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-1 h-6 rounded-full bg-purple-500" />
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
            GitHub Repository Scanner
          </h2>
        </div>
        <div className="bg-red-950/30 border border-red-800/40 rounded-xl px-5 py-4 text-sm text-red-300">
          {data.error}
        </div>
      </section>
    );
  }

  const {
    repo_url, repo_info, secrets = [], sensitive_files = [],
    suspicious_commits = [], files_with_secrets = [],
    severity_counts = {}, overall_severity,
    total_files_in_repo, total_files_scanned, rate_limit_note,
  } = data;

  const s = SEVERITY_STYLES[overall_severity] ?? SEVERITY_STYLES.None;

  // Filter secrets
  const visibleSecrets = secretFilter === "All"
    ? secrets
    : secrets.filter(s => s.severity === secretFilter);

  return (
    <section className="mb-10">
      {/* ── Header ── */}
      <div className="flex items-center gap-3 mb-5">
        <div className="w-1 h-6 rounded-full bg-purple-500" />
        <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
          GitHub Repository Scanner
        </h2>
        <a
          href={repo_url}
          target="_blank"
          rel="noreferrer"
          className="ml-auto text-xs text-blue-400 hover:text-blue-300 underline underline-offset-2 font-mono"
        >
          {repo_url.replace("https://github.com/", "")} ↗
        </a>
      </div>

      {/* ── Repo info ── */}
      <RepoInfoCard info={repo_info} />

      {/* ── Rate limit warning ── */}
      {rate_limit_note && (
        <div className="mb-5 bg-amber-950/30 border border-amber-800/40 rounded-xl px-4 py-3 text-xs text-amber-300">
          ⚠ {rate_limit_note}
        </div>
      )}

      {/* ── Summary stats ── */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
        <StatCard
          label="Overall Risk"
          value={overall_severity}
          color={s.text}
        />
        <StatCard
          label="Secrets Found"
          value={secrets.length}
          color={secrets.length > 0 ? "text-red-400" : "text-emerald-400"}
        />
        <StatCard label="Critical" value={severity_counts.Critical ?? 0} color="text-red-400" />
        <StatCard label="High"     value={severity_counts.High ?? 0}     color="text-orange-400" />
        <StatCard
          label="Files Scanned"
          value={`${total_files_scanned}/${total_files_in_repo}`}
          color="text-slate-400"
        />
      </div>

      {/* ── Clean result ── */}
      {secrets.length === 0 && sensitive_files.length === 0 && suspicious_commits.length === 0 ? (
        <div className="rounded-xl border border-emerald-800/40 bg-emerald-950/20 px-5 py-10 text-center">
          <p className="text-emerald-400 font-bold text-sm mb-1">✓ No secrets detected</p>
          <p className="text-slate-500 text-xs">
            Scanned {total_files_scanned} files — no secret patterns found.
          </p>
        </div>
      ) : (
        <>
          {/* Files with secrets */}
          <FilesScannedSection files={files_with_secrets} />

          {/* Sensitive files present */}
          <SensitiveFilesSection files={sensitive_files} />

          {/* Suspicious commits */}
          <SuspiciousCommitsSection commits={suspicious_commits} />

          {/* Secrets detail */}
          {secrets.length > 0 && (
            <div>
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest mb-3 flex items-center gap-2">
                <span className="w-1 h-4 rounded-full bg-red-500 inline-block" />
                Secret Details ({secrets.length})
              </h3>

              {/* Severity filter */}
              <div className="flex gap-2 mb-4 flex-wrap">
                {["All", "Critical", "High", "Medium"].map(sev => (
                  <button
                    key={sev}
                    onClick={() => setSecretFilter(sev)}
                    className={`px-3 py-1 rounded-lg text-xs font-semibold border transition-all ${
                      secretFilter === sev
                        ? "bg-slate-600 border-slate-500 text-white"
                        : "bg-transparent border-slate-700/40 text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    {sev}
                    {sev !== "All" && (
                      <span className="ml-1 opacity-60">
                        ({secrets.filter(s => s.severity === sev).length})
                      </span>
                    )}
                  </button>
                ))}
              </div>

              <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden">
                {/* Table header */}
                <div className="grid grid-cols-[auto_2fr_1.5fr_1fr_auto] gap-0 bg-slate-800/70 border-b border-slate-700/50 px-4 py-3">
                  {["#", "Secret Type", "File:Line", "Severity", ""].map((h, i) => (
                    <div key={i} className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                      {h}
                    </div>
                  ))}
                </div>

                <div className="divide-y divide-slate-700/30">
                  {visibleSecrets.length === 0 ? (
                    <div className="px-5 py-8 text-center text-sm text-slate-500">
                      No {secretFilter} severity secrets.
                    </div>
                  ) : (
                    visibleSecrets.map((secret, i) => (
                      <SecretCard key={i} secret={secret} index={i} />
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}

// ── Recommendation map ────────────────────────────────────────────────────────

function _secretRecommendation(type) {
  const map = {
    "AWS Access Key":        "Immediately revoke this key in AWS IAM Console. Rotate all associated permissions. Check CloudTrail for unauthorized usage.",
    "AWS Secret Key":        "Revoke in AWS IAM. Audit CloudTrail logs for any API calls made with this key.",
    "GitHub Token":          "Revoke at github.com/settings/tokens immediately. Audit repository access logs.",
    "Google API Key":        "Revoke at console.cloud.google.com/apis/credentials. Check usage logs for abuse.",
    "Stripe Secret Key":     "Revoke at dashboard.stripe.com/apikeys. Check for unauthorized charges immediately.",
    "OpenAI API Key":        "Revoke at platform.openai.com/api-keys. Check usage for unexpected charges.",
    "Private RSA Key":       "This key is permanently compromised. Generate a new key pair immediately.",
    "Database URL":          "Rotate database password immediately. Check for unauthorized queries in DB logs.",
    "Generic Password":      "Change this password immediately across all systems where it may be reused.",
    "JWT Token":             "If this is a signing secret, rotate it. All issued tokens are compromised.",
  };
  return map[type] ?? "Revoke or rotate this credential immediately. Remove from repository and add to .gitignore.";
}
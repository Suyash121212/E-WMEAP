// frontend/src/components/modules/CloudScanner.jsx
// Module 7 — Cloud & Modern Stack Misconfiguration Scanner

import { useState } from "react";
import { SeverityBadge, SEVERITY_STYLES } from "../ui/SeverityBadge";

// ── Tab config ────────────────────────────────────────────────────────────────
const TABS = [
  { id: "s3",       label: "S3 Buckets",         icon: "🪣", accent: "text-orange-400",  activeCls: "bg-orange-900/40 border-orange-600/60 text-orange-300" },
  { id: "subdomains",label: "Subdomain Takeover", icon: "⇝",  accent: "text-red-400",    activeCls: "bg-red-900/40 border-red-600/60 text-red-300" },
  { id: "services", label: "Cloud Services",      icon: "☁",  accent: "text-blue-400",   activeCls: "bg-blue-900/40 border-blue-600/60 text-blue-300" },
];

// ── Shared helpers ────────────────────────────────────────────────────────────
function StatCard({ label, value, color = "text-slate-200", sub }) {
  return (
    <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-4">
      <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">{label}</p>
      <p className={`text-2xl font-black font-mono ${color}`}>{value}</p>
      {sub && <p className="text-[10px] text-slate-600 mt-1">{sub}</p>}
    </div>
  );
}

function SummaryBanner({ text, severity }) {
  const color =
    severity === "Critical" ? "bg-red-950/40 border-red-800/50 text-red-300" :
    severity === "High"     ? "bg-orange-950/40 border-orange-800/50 text-orange-300" :
    severity === "Medium"   ? "bg-amber-950/40 border-amber-800/50 text-amber-300" :
    severity === "None"     ? "bg-emerald-950/30 border-emerald-800/40 text-emerald-300" :
                              "bg-slate-800/40 border-slate-700/40 text-slate-400";
  return (
    <div className={`rounded-xl border px-4 py-3 mb-5 text-xs font-medium ${color}`}>
      {text}
    </div>
  );
}

function TechniqueBox({ technique }) {
  if (!technique?.name) return null;
  return (
    <div className="mt-3 rounded-lg border border-orange-900/50 bg-orange-950/20 overflow-hidden">
      <div className="px-4 py-2 bg-orange-950/40 border-b border-orange-900/40">
        <span className="text-[10px] uppercase tracking-widest text-orange-400 font-semibold">
          ⚔ Exploitation: {technique.name}
        </span>
      </div>
      <div className="p-4 space-y-3">
        {technique.steps?.length > 0 && (
          <ol className="space-y-1.5">
            {technique.steps.map((step, i) => (
              <li key={i} className="flex gap-2 text-xs text-slate-300">
                <span className="text-orange-500 font-mono font-bold w-4 flex-shrink-0">{i + 1}.</span>
                <span className="font-mono break-all">{step}</span>
              </li>
            ))}
          </ol>
        )}
        {technique.impact && (
          <div className="bg-red-950/30 border border-red-900/40 rounded px-3 py-2">
            <p className="text-[10px] text-red-400 font-semibold uppercase tracking-widest mb-0.5">Impact</p>
            <p className="text-xs text-red-200">{technique.impact}</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── S3 Section ────────────────────────────────────────────────────────────────

function S3FileList({ files, sensitiveFiles }) {
  if (!files?.length) return null;
  const sensitiveSet = new Set(sensitiveFiles ?? []);
  return (
    <div className="mt-3">
      <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
        Files in Bucket ({files.length})
      </p>
      <div className="max-h-40 overflow-y-auto rounded-lg border border-slate-700/40 bg-slate-900/60 p-3 space-y-1">
        {files.map((f, i) => (
          <div key={i} className={`flex items-center justify-between gap-3 text-[11px] font-mono ${
            sensitiveSet.has(f.key) ? "text-red-300" : "text-slate-400"
          }`}>
            <span className="truncate">{sensitiveSet.has(f.key) ? "⚠ " : ""}{f.key}</span>
            <span className="text-slate-600 flex-shrink-0">{_formatBytes(f.size)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function S3FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const s = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.Info;

  return (
    <div className={`border-b border-slate-700/30 last:border-0 ${
      finding.severity === "Critical" ? "border-l-2 border-l-red-500" :
      finding.severity === "High"     ? "border-l-2 border-l-orange-500" :
      finding.severity === "Medium"   ? "border-l-2 border-l-amber-500" :
      "border-l-2 border-l-slate-600"
    }`}>
      <div
        className="flex items-center gap-3 px-4 py-3.5 cursor-pointer hover:bg-slate-700/20 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <span className={`text-lg ${finding.public_read ? "text-red-400" : "text-amber-400"}`}>
          {finding.public_read ? "🪣" : "🔒"}
        </span>
        <div className="flex-1 min-w-0">
          <p className="font-mono text-xs font-bold text-slate-200">{finding.bucket_name}</p>
          <p className="text-[10px] text-slate-500 mt-0.5">
            {finding.public_read ? `${finding.file_count} files exposed` : "Bucket exists, access blocked"}
          </p>
        </div>
        {finding.public_read && (
          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-900/50 text-red-300 border border-red-700/40 uppercase">
            Public Read
          </span>
        )}
        <SeverityBadge level={finding.severity} />
        <span className={`text-slate-500 text-xs transition-transform ${expanded ? "rotate-180" : ""}`}>▾</span>
      </div>

      {expanded && (
        <div className="px-5 pb-5 pt-1 bg-slate-900/50 border-t border-slate-700/30 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Bucket URL</p>
              <a href={finding.url} target="_blank" rel="noreferrer"
                className="font-mono text-xs text-blue-400 hover:text-blue-300 underline break-all">
                {finding.url}
              </a>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">HTTP Status</p>
              <span className={`font-mono text-xs font-bold ${
                finding.status_code === 200 ? "text-red-400" : "text-amber-400"
              }`}>{finding.status_code}</span>
            </div>
          </div>

          <div>
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Finding</p>
            <p className="text-xs text-slate-300">{finding.finding}</p>
          </div>

          {finding.sensitive_files?.length > 0 && (
            <div className="bg-red-950/30 border border-red-900/40 rounded-lg px-3 py-2">
              <p className="text-[10px] uppercase tracking-widest text-red-400 font-semibold mb-2">
                🚨 Sensitive Files Detected
              </p>
              <div className="flex flex-wrap gap-2">
                {finding.sensitive_files.map((f, i) => (
                  <span key={i} className="font-mono text-[10px] px-2 py-0.5 bg-red-900/40 text-red-300 border border-red-800/40 rounded">
                    {f}
                  </span>
                ))}
              </div>
            </div>
          )}

          <S3FileList files={finding.files} sensitiveFiles={finding.sensitive_files} />

          <div className="bg-emerald-950/30 border border-emerald-900/40 rounded-lg px-3 py-2">
            <p className="text-[10px] uppercase tracking-widest text-emerald-400 font-semibold mb-1">Remediation</p>
            <p className="text-xs text-slate-300">
              Enable S3 Block Public Access at the account level. Review bucket ACLs and bucket policies.
              Use least-privilege IAM roles. Enable S3 server access logging.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function S3Section({ data }) {
  if (!data) return null;
  const { findings = [], buckets_checked, buckets_found, overall_severity, summary } = data;
  const publicBuckets = findings.filter(f => f.public_read);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Checked"       value={buckets_checked} color="text-slate-300" />
        <StatCard label="Found"         value={buckets_found}   color={buckets_found > 0 ? "text-amber-400" : "text-emerald-400"} />
        <StatCard label="Public Read"   value={publicBuckets.length} color={publicBuckets.length > 0 ? "text-red-400" : "text-emerald-400"} />
        <StatCard label="Overall Risk"  value={overall_severity} color={SEVERITY_STYLES[overall_severity]?.text ?? "text-slate-400"} />
      </div>

      <SummaryBanner text={summary} severity={overall_severity} />

      {findings.length === 0 ? (
        <div className="rounded-xl border border-emerald-800/40 bg-emerald-950/20 px-5 py-10 text-center">
          <p className="text-emerald-400 font-semibold text-sm">✓ No S3 buckets found</p>
          <p className="text-slate-500 text-xs mt-1">Checked {buckets_checked} candidate bucket names</p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden divide-y divide-slate-700/30">
          {findings.map((f, i) => <S3FindingCard key={i} finding={f} />)}
        </div>
      )}
    </div>
  );
}

// ── Subdomain Section ─────────────────────────────────────────────────────────

function SubdomainFindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const s = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.Info;

  return (
    <div className={`border-b border-slate-700/30 last:border-0 ${
      finding.exploitable ? (
        finding.severity === "Critical" ? "border-l-2 border-l-red-500" : "border-l-2 border-l-orange-500"
      ) : "border-l-2 border-l-slate-600"
    }`}>
      <div
        className="flex items-center gap-3 px-4 py-3.5 cursor-pointer hover:bg-slate-700/20 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold text-slate-200 truncate">{finding.subdomain}</span>
            {finding.exploitable && (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-900/50 text-red-300 border border-red-700/40 uppercase flex-shrink-0">
                Takeover
              </span>
            )}
          </div>
          <p className="text-[10px] text-slate-500 mt-0.5 font-mono">
            CNAME → {finding.cname} ({finding.service})
          </p>
        </div>
        <SeverityBadge level={finding.severity} />
        <span className={`text-slate-500 text-xs transition-transform ${expanded ? "rotate-180" : ""}`}>▾</span>
      </div>

      {expanded && (
        <div className="px-5 pb-5 pt-1 bg-slate-900/50 border-t border-slate-700/30 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Subdomain</p>
              <p className="font-mono text-xs text-slate-200">{finding.subdomain}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">CNAME Target</p>
              <p className="font-mono text-xs text-blue-400">{finding.cname}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Service</p>
              <p className="text-xs text-slate-300">{finding.service}</p>
            </div>
            {finding.fingerprint && (
              <div>
                <p className="text-[10px] uppercase tracking-widest text-red-400 mb-1">Takeover Fingerprint</p>
                <code className="font-mono text-xs text-red-300 bg-slate-900 px-2 py-1 rounded block">
                  {finding.fingerprint}
                </code>
              </div>
            )}
          </div>

          <div>
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Description</p>
            <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>
          </div>

          <TechniqueBox technique={finding.technique} />

          <div className="bg-emerald-950/30 border border-emerald-900/40 rounded-lg px-3 py-2">
            <p className="text-[10px] uppercase tracking-widest text-emerald-400 font-semibold mb-1">Remediation</p>
            <p className="text-xs text-slate-300">
              Remove the dangling DNS CNAME record immediately. Audit all DNS records regularly.
              Implement a process to remove DNS records when deprovisioning services.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function SubdomainSection({ data }) {
  if (!data) return null;
  const {
    subdomains_found, subdomains_list = [], takeover_findings = [],
    exploitable_count, overall_severity, summary, sources,
  } = data;

  const [showAll, setShowAll] = useState(false);
  const exploitable = takeover_findings.filter(f => f.exploitable);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Subdomains Found" value={subdomains_found} color="text-slate-300" />
        <StatCard label="Vulnerable"       value={exploitable_count} color={exploitable_count > 0 ? "text-red-400" : "text-emerald-400"} />
        <StatCard label="crt.sh"           value={sources?.crtsh ?? 0} color="text-blue-400" sub="cert transparency" />
        <StatCard label="HackerTarget"     value={sources?.hackertarget ?? 0} color="text-purple-400" sub="DNS enum" />
      </div>

      <SummaryBanner text={summary} severity={overall_severity} />

      {/* Takeover findings */}
      {takeover_findings.length > 0 && (
        <div>
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest mb-3 flex items-center gap-2">
            <span className="w-1 h-4 rounded-full bg-red-500 inline-block" />
            Takeover Candidates ({takeover_findings.length})
          </h3>
          <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden">
            <div className="grid grid-cols-[1fr_auto_auto] bg-slate-800/70 border-b border-slate-700/50 px-4 py-3">
              {["Subdomain / CNAME", "Severity", ""].map((h, i) => (
                <div key={i} className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{h}</div>
              ))}
            </div>
            <div className="divide-y divide-slate-700/30">
              {takeover_findings.map((f, i) => <SubdomainFindingCard key={i} finding={f} />)}
            </div>
          </div>
        </div>
      )}

      {/* All subdomains list */}
      {subdomains_list.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest">
              All Discovered Subdomains ({subdomains_list.length})
            </h3>
            <button
              onClick={() => setShowAll(!showAll)}
              className="text-[10px] text-blue-400 hover:text-blue-300"
            >
              {showAll ? "Show less" : "Show all"}
            </button>
          </div>
          <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
            {(showAll ? subdomains_list : subdomains_list.slice(0, 20)).map((sub, i) => (
              <span key={i} className={`font-mono text-[10px] px-2 py-0.5 rounded border ${
                takeover_findings.some(f => f.subdomain === sub && f.exploitable)
                  ? "bg-red-900/30 text-red-300 border-red-800/40"
                  : "bg-slate-800 text-slate-500 border-slate-700/40"
              }`}>
                {sub}
              </span>
            ))}
          </div>
        </div>
      )}

      {takeover_findings.length === 0 && subdomains_list.length === 0 && (
        <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 px-5 py-10 text-center">
          <p className="text-slate-400 text-sm">No subdomains discovered</p>
          <p className="text-slate-600 text-xs mt-1">crt.sh and HackerTarget returned no results</p>
        </div>
      )}
    </div>
  );
}

// ── Cloud Services Section ────────────────────────────────────────────────────

function ServiceFindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const s = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.Info;

  const SERVICE_ICONS = {
    "docker": "🐳", "kubernetes": "☸", "elastic": "🔍",
    "jenkins": "🔧", "prometheus": "📊", "grafana": "📈",
    "swagger": "📋", "jupyter": "📓", "phpmyadmin": "🗄",
    "consul": "🏛", "rabbitmq": "🐰", "airflow": "💨",
  };
  const icon = SERVICE_ICONS[finding.verifier_key] ?? "☁";

  return (
    <div className={`border-b border-slate-700/30 last:border-0 ${
      finding.severity === "Critical" ? "border-l-2 border-l-red-500" :
      finding.severity === "High"     ? "border-l-2 border-l-orange-500" :
      finding.severity === "Medium"   ? "border-l-2 border-l-amber-500" :
      "border-l-2 border-l-slate-600"
    }`}>
      <div
        className="flex items-center gap-3 px-4 py-3.5 cursor-pointer hover:bg-slate-700/20 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <span className="text-lg flex-shrink-0">{icon}</span>
        <div className="flex-1 min-w-0">
          <p className="font-semibold text-xs text-slate-200">{finding.service}</p>
          <p className="font-mono text-[10px] text-blue-400 mt-0.5 truncate">{finding.url}</p>
        </div>
        <span className={`font-mono text-[10px] px-2 py-0.5 rounded border ${
          finding.status_code === 200
            ? "bg-red-900/30 text-red-300 border-red-700/40"
            : "bg-amber-900/30 text-amber-300 border-amber-700/40"
        }`}>{finding.status_code}</span>
        <SeverityBadge level={finding.severity} />
        <span className={`text-slate-500 text-xs transition-transform ${expanded ? "rotate-180" : ""}`}>▾</span>
      </div>

      {expanded && (
        <div className="px-5 pb-5 pt-1 bg-slate-900/50 border-t border-slate-700/30 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Description</p>
              <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Accessible URL</p>
              <a href={finding.url} target="_blank" rel="noreferrer"
                className="font-mono text-xs text-blue-400 hover:text-blue-300 underline break-all">
                {finding.url}
              </a>
            </div>
          </div>

          {finding.content_preview && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1.5">Response Preview</p>
              <div className="bg-slate-900 rounded-lg px-3 py-2 border border-slate-700/50 max-h-24 overflow-y-auto">
                <pre className="text-[10px] text-green-400 font-mono whitespace-pre-wrap break-all">
                  {finding.content_preview}
                </pre>
              </div>
            </div>
          )}

          <TechniqueBox technique={finding.technique} />

          <div className="bg-emerald-950/30 border border-emerald-900/40 rounded-lg px-3 py-2">
            <p className="text-[10px] uppercase tracking-widest text-emerald-400 font-semibold mb-1">Remediation</p>
            <p className="text-xs text-slate-300">{finding.remediation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function ServicesSection({ data }) {
  if (!data) return null;
  const { findings = [], services_checked, overall_severity, summary } = data;
  const critical = findings.filter(f => f.severity === "Critical");

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Checks Run"   value={services_checked} color="text-slate-300" />
        <StatCard label="Exposed"      value={findings.length}  color={findings.length > 0 ? "text-red-400" : "text-emerald-400"} />
        <StatCard label="Critical"     value={critical.length}  color={critical.length > 0 ? "text-red-400" : "text-emerald-400"} />
        <StatCard label="Overall Risk" value={overall_severity} color={SEVERITY_STYLES[overall_severity]?.text ?? "text-slate-400"} />
      </div>

      <SummaryBanner text={summary} severity={overall_severity} />

      {findings.length === 0 ? (
        <div className="rounded-xl border border-emerald-800/40 bg-emerald-950/20 px-5 py-10 text-center">
          <p className="text-emerald-400 font-semibold text-sm">✓ No exposed cloud services found</p>
          <p className="text-slate-500 text-xs mt-1">Checked {services_checked} service endpoints</p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-700/50 bg-slate-800/20 overflow-hidden">
          <div className="grid grid-cols-[auto_1fr_auto_auto_auto] bg-slate-800/70 border-b border-slate-700/50 px-4 py-3 gap-3">
            {["", "Service", "Status", "Severity", ""].map((h, i) => (
              <div key={i} className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{h}</div>
            ))}
          </div>
          <div className="divide-y divide-slate-700/30">
            {findings.map((f, i) => <ServiceFindingCard key={i} finding={f} />)}
          </div>
        </div>
      )}
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
      <div className="flex gap-2 mb-6">
        {[1,2,3].map(i => <div key={i} className="h-10 w-36 bg-slate-800/50 rounded-xl border border-slate-700/40" />)}
      </div>
      <div className="grid grid-cols-4 gap-3 mb-5">
        {[1,2,3,4].map(i => <div key={i} className="h-20 bg-slate-800/40 rounded-xl border border-slate-700/40" />)}
      </div>
      <div className="h-48 bg-slate-800/20 rounded-xl border border-slate-700/40" />
    </section>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function CloudScanner({ data, loading }) {
  const [activeTab, setActiveTab] = useState("s3");

  if (loading) return <LoadingSkeleton />;
  if (!data)   return null;

  if (data.error) {
    return (
      <section className="mb-10">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-1 h-6 rounded-full bg-sky-500" />
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">Cloud Scanner</h2>
        </div>
        <div className="bg-red-950/30 border border-red-800/40 rounded-xl px-5 py-4 text-sm text-red-300">{data.error}</div>
      </section>
    );
  }

  const { s3, subdomains, services, overall_severity, total_findings } = data;
  const os = SEVERITY_STYLES[overall_severity] ?? SEVERITY_STYLES.None;

  const tabCounts = {
    s3:         s3?.findings?.length ?? 0,
    subdomains: subdomains?.takeover_findings?.filter(f => f.exploitable)?.length ?? 0,
    services:   services?.findings?.length ?? 0,
  };

  return (
    <section className="mb-10">
      {/* ── Header ── */}
      <div className="flex items-center gap-3 mb-5">
        <div className="w-1 h-6 rounded-full bg-sky-500" />
        <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
          Cloud & Modern Stack Scanner
        </h2>
        <div className="ml-auto flex items-center gap-3">
          <span className={`text-xs font-bold ${os.text}`}>{overall_severity} Risk</span>
          <span className="text-xs text-slate-500">{total_findings} findings</span>
        </div>
      </div>

      {/* ── Tab bar ── */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {TABS.map(tab => {
          const count    = tabCounts[tab.id];
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border text-xs font-semibold transition-all ${
                isActive ? tab.activeCls : "bg-slate-800/40 border-slate-700/40 text-slate-400 hover:border-slate-500"
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
              {count > 0 ? (
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${
                  SEVERITY_STYLES["High"]?.badge
                }`}>{count}</span>
              ) : (
                <span className="text-[10px] text-emerald-400 font-semibold">✓</span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Tab content ── */}
      {activeTab === "s3"        && <S3Section        data={s3} />}
      {activeTab === "subdomains"&& <SubdomainSection data={subdomains} />}
      {activeTab === "services"  && <ServicesSection  data={services} />}
    </section>
  );
}

// ── Utility ───────────────────────────────────────────────────────────────────
function _formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}
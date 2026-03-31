// components/ui/SeverityBadge.jsx
// Shared severity/status badge used across all scanner modules

export const SEVERITY_STYLES = {
  Critical: {
    badge: "bg-red-950 text-red-300 border border-red-800",
    dot: "bg-red-400",
    text: "text-red-400",
    bar: "bg-red-500",
    glow: "shadow-[0_0_8px_rgba(239,68,68,0.4)]",
  },
  High: {
    badge: "bg-red-900/60 text-red-300 border border-red-700/50",
    dot: "bg-red-400",
    text: "text-red-400",
    bar: "bg-red-500",
    glow: "shadow-[0_0_6px_rgba(239,68,68,0.3)]",
  },
  Medium: {
    badge: "bg-amber-900/60 text-amber-300 border border-amber-700/50",
    dot: "bg-amber-400",
    text: "text-amber-400",
    bar: "bg-amber-500",
    glow: "shadow-[0_0_6px_rgba(245,158,11,0.3)]",
  },
  Low: {
    badge: "bg-blue-900/60 text-blue-300 border border-blue-700/50",
    dot: "bg-blue-400",
    text: "text-blue-400",
    bar: "bg-blue-400",
    glow: "",
  },
  None: {
    badge: "bg-emerald-900/60 text-emerald-300 border border-emerald-700/50",
    dot: "bg-emerald-400",
    text: "text-emerald-400",
    bar: "bg-emerald-500",
    glow: "",
  },
  Info: {
    badge: "bg-slate-800 text-slate-300 border border-slate-600",
    dot: "bg-slate-400",
    text: "text-slate-400",
    bar: "bg-slate-500",
    glow: "",
  },
};

// Inline badge pill  e.g.  <SeverityBadge level="High" />
export function SeverityBadge({ level, label }) {
  const s = SEVERITY_STYLES[level] ?? SEVERITY_STYLES.Info;
  const display = label ?? level;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-wide ${s.badge}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {display}
    </span>
  );
}

// Status badge (Secure / Missing / Weak Configuration)
export function StatusBadge({ status }) {
  const map = {
    Secure: "bg-emerald-900/50 text-emerald-300 border border-emerald-700/40",
    Missing: "bg-red-900/50 text-red-300 border border-red-700/40",
    "Weak Configuration": "bg-amber-900/50 text-amber-300 border border-amber-700/40",
    Present: "bg-blue-900/50 text-blue-300 border border-blue-700/40",
  };
  const cls = map[status] ?? "bg-slate-800 text-slate-300 border border-slate-600";
  return (
    <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${cls}`}>
      {status}
    </span>
  );
}   
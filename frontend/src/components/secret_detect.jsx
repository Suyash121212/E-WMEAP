// SecretScanResult.jsx
// Drop this component into your project and render it in App.jsx like:
//   {secretResult && <SecretScanResult data={secretResult} />}

const confidenceBadge = (level) => {
  if (level === "High")   return "bg-red-100 text-red-700 border border-red-200";
  if (level === "Medium") return "bg-orange-100 text-orange-700 border border-orange-200";
  return "bg-blue-100 text-blue-700 border border-blue-200";
};

const severityBadgeBg = (severity) => {
  if (severity === "High")   return "bg-red-100 text-red-700 border border-red-200";
  if (severity === "Medium") return "bg-orange-100 text-orange-700 border border-orange-200";
  if (severity === "Low")    return "bg-blue-100 text-blue-700 border border-blue-200";
  return "bg-green-100 text-green-700 border border-green-200";
};

const sourceLabel = (source) =>
  source === "inline_script" ? "Inline Script" : "External JS";

const sourceColor = (source) =>
  source === "inline_script"
    ? "bg-purple-100 text-purple-700 border border-purple-200"
    : "bg-gray-100 text-gray-600 border border-gray-200";

export default function SecretScanResult({ data }) {
  const { total_files_scanned, total_secrets_found, secrets, severity, summary } = data;

  return (
    <section className="mb-8">

      {/* ── Section header ── */}
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-base font-bold text-gray-800">Exposed Secrets</h2>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-400 font-medium">
            {total_files_scanned} file{total_files_scanned !== 1 ? "s" : ""} scanned
          </span>
          <span className={`px-3 py-1 rounded-full text-xs font-bold ${severityBadgeBg(severity)}`}>
            {severity === "None" ? "Clean" : `${severity} Severity`}
          </span>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">

        {/* ── Summary bar ── */}
        <div className={`px-5 py-3 text-xs font-medium border-b border-gray-100
          ${severity === "High"   ? "bg-red-50 text-red-700" :
            severity === "Medium" ? "bg-orange-50 text-orange-700" :
            severity === "Low"    ? "bg-blue-50 text-blue-700" :
                                    "bg-green-50 text-green-700"}`}>
          {summary}
        </div>

        {/* ── Empty state ── */}
        {total_secrets_found === 0 ? (
          <div className="px-5 py-8 text-center text-sm text-gray-400">
            No secrets or sensitive patterns detected in client-side code.
          </div>
        ) : (

          /* ── Secrets list ── */
          <div className="divide-y divide-gray-50 max-h-[480px] overflow-y-auto">
            {secrets.map((item, i) => (
              <div
                key={i}
                className={`px-5 py-4 hover:bg-gray-50 transition-colors
                  ${item.confidence === "High" ? "border-l-4 border-red-400" :
                    item.confidence === "Medium" ? "border-l-4 border-orange-400" :
                    "border-l-4 border-blue-300"}`}
              >
                {/* Row 1 — type + badges */}
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span className="font-mono font-bold text-xs text-gray-800 bg-gray-100 px-2 py-0.5 rounded">
                    {item.type}
                  </span>
                  <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${confidenceBadge(item.confidence)}`}>
                    {item.confidence} Confidence
                  </span>
                  <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${sourceColor(item.source)}`}>
                    {sourceLabel(item.source)}
                  </span>
                </div>

                {/* Row 2 — snippet */}
                <div className="bg-gray-900 rounded-lg px-3 py-2 mb-2">
                  <code className="text-xs text-green-400 font-mono break-all leading-relaxed">
                    {item.snippet}
                  </code>
                </div>

                {/* Row 3 — file source */}
                {item.file && item.file !== "inline" && (
                  <p className="text-xs text-gray-400 truncate">
                    <span className="font-semibold text-gray-500">File: </span>
                    {item.file}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

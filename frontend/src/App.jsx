import React, { useState } from "react";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [bannerResult, setBannerResult] = useState(null);
  const [portResult, setPortResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const startScan = async () => {
    if (!url.trim()) return;

    setLoading(true);
    setResult(null);
    setBannerResult(null);
    setPortResult(null);
    setError(null);

    try {
      const [headerRes, bannerRes, portRes] = await Promise.all([
        fetch("http://127.0.0.1:5000/scan/header", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        }),
        fetch("http://127.0.0.1:5000/scan/banner", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        }),
        fetch("http://127.0.0.1:5000/scan/ports", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        }),
      ]);

      const headerData = await headerRes.json();
      const bannerData = await bannerRes.json();
      const portData   = await portRes.json();

      setResult(headerData);
      setBannerResult(bannerData);
      setPortResult(portData);
    } catch (err) {
      setError("Failed to connect to the scanner backend. Is Flask running?");
    } finally {
      setLoading(false);
    }
  };

  /* ── Colour helpers ── */
  const severityColor = (severity) => {
    if (severity === "High")   return "text-red-600";
    if (severity === "Medium") return "text-orange-500";
    if (severity === "Low")    return "text-blue-500";
    return "text-green-600";
  };

  const severityBadgeBg = (severity) => {
    if (severity === "High")   return "bg-red-100 text-red-700 border border-red-200";
    if (severity === "Medium") return "bg-orange-100 text-orange-700 border border-orange-200";
    if (severity === "Low")    return "bg-blue-100 text-blue-700 border border-blue-200";
    return "bg-green-100 text-green-700 border border-green-200";
  };

  const statusBadge = (status) => {
    if (status === "Secure")  return "bg-green-100 text-green-700";
    if (status === "Missing") return "bg-red-100 text-red-700";
    return "bg-orange-100 text-orange-700";
  };

  /* ── Banner info row ── */
  const InfoRow = ({ label, value, mono = false }) => (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs font-semibold uppercase tracking-widest text-gray-400">
        {label}
      </span>
      <span className={`text-sm text-gray-800 break-all ${mono ? "font-mono" : "font-medium"}`}>
        {value || "—"}
      </span>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-50">

      {/* ── Top Nav Bar ── */}
      <header className="bg-gray-900 text-white px-8 py-4 flex items-center gap-3 shadow-md">
        <div className="flex items-center gap-2">
          <span className="text-blue-400 text-xl">⬡</span>
          <span className="font-bold text-lg tracking-tight">E-WMEAP</span>
        </div>
        <span className="ml-2 text-gray-400 text-sm hidden sm:block">
          Enterprise Web Misconfiguration &amp; Exposure Assessment Platform
        </span>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-10">

        {/* ── Page Title ── */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Security Scanner</h1>
          <p className="text-gray-500 text-sm mt-1">
            Analyse headers, banners, and exposure signals for a target URL.
          </p>
        </div>

        {/* ── URL Input ── */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 mb-8">
          <label className="block text-xs font-semibold uppercase tracking-widest text-gray-400 mb-2">
            Target URL
          </label>
          <div className="flex gap-3">
            <input
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && startScan()}
              className="flex-1 px-4 py-2.5 border border-gray-200 rounded-lg text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
            />
            <button
              onClick={startScan}
              disabled={loading}
              className="px-6 py-2.5 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 active:scale-95 transition font-semibold disabled:opacity-60 disabled:cursor-not-allowed whitespace-nowrap"
            >
              {loading ? "Scanning…" : "Run Scan"}
            </button>
          </div>
        </div>

        {/* ── Error ── */}
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg px-4 py-3">
            {error}
          </div>
        )}

        {/* ── Loading ── */}
        {loading && (
          <div className="flex items-center gap-3 text-gray-500 text-sm mb-6">
            <svg className="animate-spin h-4 w-4 text-blue-500" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            Running header and banner analysis…
          </div>
        )}

        {/* ═══════════════════════════════════════════
            MODULE 1 — Header Security Findings
        ════════════════════════════════════════════ */}
        {result && (
          <section className="mb-8">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-base font-bold text-gray-800">
                Header Security Analysis
              </h2>
              <span className="text-xs text-gray-400 font-medium">
                {result.total_headers_checked} headers checked
              </span>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 border-b border-gray-100 text-left">
                      <th className="px-4 py-3 text-xs font-semibold uppercase tracking-widest text-gray-400">Header</th>
                      <th className="px-4 py-3 text-xs font-semibold uppercase tracking-widest text-gray-400">Value</th>
                      <th className="px-4 py-3 text-xs font-semibold uppercase tracking-widest text-gray-400">Status</th>
                      <th className="px-4 py-3 text-xs font-semibold uppercase tracking-widest text-gray-400">Severity</th>
                      <th className="px-4 py-3 text-xs font-semibold uppercase tracking-widest text-gray-400">Impact</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.findings.map((item, i) => (
                      <tr key={i} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                        <td className="px-4 py-3 font-medium text-gray-800 font-mono text-xs">{item.header}</td>
                        <td className="px-4 py-3 text-gray-500 font-mono text-xs max-w-xs truncate">{item.value || "Not Present"}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${statusBadge(item.status)}`}>
                            {item.status}
                          </span>
                        </td>
                        <td className={`px-4 py-3 font-bold text-xs ${severityColor(item.severity)}`}>
                          {item.severity}
                        </td>
                        <td className="px-4 py-3 text-gray-500 text-xs">{item.impact}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        )}

        {/* ═══════════════════════════════════════════
            MODULE 2 — Server Banner Detection
        ════════════════════════════════════════════ */}
        {bannerResult && (
          <section className="mb-8">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-base font-bold text-gray-800">
                Server Information
              </h2>
              <span className={`px-3 py-1 rounded-full text-xs font-bold ${severityBadgeBg(bannerResult.severity)}`}>
                {bannerResult.severity === "None" ? "Not Exposed" : `${bannerResult.severity} Severity`}
              </span>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-5">

              {/* Info grid */}
              <div className="grid grid-cols-2 gap-x-8 gap-y-5 sm:grid-cols-4 mb-6">
                <InfoRow label="Server"     value={bannerResult.server}     mono />
                <InfoRow label="Powered By" value={bannerResult.powered_by} mono />
                <InfoRow label="Technology" value={bannerResult.technology} />
                <InfoRow label="Version"    value={bannerResult.version}    mono />
              </div>

              <div className="border-t border-gray-100 pt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                {/* Impact */}
                <div>
                  <p className="text-xs font-semibold uppercase tracking-widest text-gray-400 mb-1">
                    Impact
                  </p>
                  <p className="text-sm text-gray-700 leading-relaxed">
                    {bannerResult.impact}
                  </p>
                </div>
                {/* Recommendation */}
                <div>
                  <p className="text-xs font-semibold uppercase tracking-widest text-gray-400 mb-1">
                    Recommendation
                  </p>
                  <p className="text-sm text-gray-700 leading-relaxed">
                    {bannerResult.recommendation}
                  </p>
                </div>
              </div>

            </div>
          </section>
        )}

        {/* ═══════════════════════════════════════════
            MODULE 3 — Port Scanner
        ════════════════════════════════════════════ */}
        {portResult && (
          <section className="mb-8">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-base font-bold text-gray-800">Open Ports</h2>
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-400 font-medium">
                  {portResult.total_open_ports} open port{portResult.total_open_ports !== 1 ? "s" : ""} found
                </span>
                <span className={`px-3 py-1 rounded-full text-xs font-bold ${severityBadgeBg(portResult.severity)}`}>
                  {portResult.severity === "None" ? "No Risk" : `${portResult.severity} Risk`}
                </span>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">

              {/* Risk summary bar */}
              <div className={`px-5 py-3 text-xs font-medium border-b border-gray-100
                ${portResult.severity === "High"   ? "bg-red-50 text-red-700" :
                  portResult.severity === "Medium" ? "bg-orange-50 text-orange-700" :
                  portResult.severity === "Low"    ? "bg-blue-50 text-blue-700" :
                                                     "bg-green-50 text-green-700"}`}>
                {portResult.risk_summary}
              </div>

              {portResult.open_ports.length === 0 ? (
                <div className="px-5 py-8 text-center text-sm text-gray-400">
                  No open ports detected in the scanned range.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="table-auto w-full text-sm">
                    <thead>
                      <tr className="bg-gray-50 border-b border-gray-100 text-left">
                        <th className="px-4 py-3 text-xs font-semibold uppercase tracking-widest text-gray-400 w-20">Port</th>
                        <th className="px-4 py-3 text-xs font-semibold uppercase tracking-widest text-gray-400 w-36">Service</th>
                        <th className="px-4 py-3 text-xs font-semibold uppercase tracking-widest text-gray-400">Possible Attacks</th>
                      </tr>
                    </thead>
                    <tbody>
                      {portResult.open_ports.map((item, i) => (
                        <tr key={i} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">

                          {/* Port number */}
                          <td className="px-4 py-3">
                            <span className="font-mono font-bold text-gray-800 bg-gray-100 px-2 py-0.5 rounded text-xs">
                              {item.port}
                            </span>
                          </td>

                          {/* Service */}
                          <td className="px-4 py-3">
                            <span className="font-semibold text-gray-700 text-xs">{item.service}</span>
                          </td>

                          {/* Attack tags */}
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-1.5">
                              {item.attacks.map((atk, j) => (
                                <span
                                  key={j}
                                  className="px-2 py-0.5 rounded-md text-xs font-medium bg-red-50 text-red-700 border border-red-100"
                                >
                                  {atk}
                                </span>
                              ))}
                            </div>
                          </td>

                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </section>
        )}

      </main>
    </div>
  );
}

export default App;
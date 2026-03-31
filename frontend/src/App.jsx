import { useState } from "react";
import HeaderScanner from "./components/modules/HeaderScanner";
import PortScanner from "./components/modules/PortScanner";
import DirectoryScanner from "./components/modules/DirectoryScanner";
import BusinessLogicScanner from "./components/modules/BusinessLogicScanner";


const API = "http://127.0.0.1:5000";

export default function App() {
  const [url, setUrl] = useState("");

  // Individual module data states
  const [headerData, setHeaderData] = useState(null);
  const [tlsData, setTlsData] = useState(null);
  const [portData, setPortData] = useState(null);
  const [dirData, setDirData] = useState(null);
  const [businessData, setBusinessData] = useState(null);

  // Individual loading states
  const [loadingHeader, setLoadingHeader] = useState(false);
  const [loadingTls, setLoadingTls] = useState(false);
  const [loadingPort, setLoadingPort] = useState(false);
  const [loadingDirectory, setLoadingDirectory] = useState(false);
  const [loadingBusiness, setLoadingBusiness] = useState(false);
  const [jwtToken, setJwtToken] = useState("");   // optional manual JWT input

  const [error, setError] = useState(null);
  const [scanned, setScanned] = useState(false);

  // Individual scan functions
  const scanHeader = async () => {
    if (!url.trim()) return;
    setLoadingHeader(true);
    setError(null);

    try {
      const response = await fetch(`${API}/scan/header`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      setHeaderData(data);
      setScanned(true);
    } catch (err) {
      setError("Cannot reach header scanner backend");
    } finally {
      setLoadingHeader(false);
    }
  };

  const scanTls = async () => {
    if (!url.trim()) return;
    setLoadingTls(true);
    setError(null);

    try {
      const response = await fetch(`${API}/scan/tls`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      setTlsData(data.error ? null : data);
      setScanned(true);
    } catch (err) {
      setError("Cannot reach TLS scanner backend");
    } finally {
      setLoadingTls(false);
    }
  };

  const scanPorts = async () => {
    if (!url.trim()) return;
    setLoadingPort(true);
    setError(null);

    try {
      const response = await fetch(`${API}/scan/ports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      setPortData(data);
      setScanned(true);
    } catch (err) {
      setError("Cannot reach port scanner backend");
    } finally {
      setLoadingPort(false);
    }
  };
  const scanDirectories = async () => {
    if (!url.trim()) return;
    setLoadingDirectory(true);
    setError(null);


    try {
      const response = await fetch(`${API}/scan/directories`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      // Handle directory scanner data if needed
      setDirData(data);
      setScanned(true);

    } catch (err) {
      setError("Cannot reach directory scanner backend");
    }
    finally {
      setLoadingDirectory(false);
    }

  };

  // Business Logic Scanner (optional, can be triggered separately or included in scanAll)
  const scanBusiness = async () => {
    if (!url.trim()) return;
    setLoadingBusiness(true);
    setBusinessData(null);
    try {
      const res = await fetch(`${API}/scan/business`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, jwt_token: jwtToken }),
      });
      const data = await res.json();
      setBusinessData(data);
      setScanned(true);
    } catch {
      setError("Cannot reach business logic scanner backend");
    } finally {
      setLoadingBusiness(false);
    }
  };

  // Scan all modules
  const scanAll = async () => {
    if (!url.trim()) return;
    setLoadingHeader(true);
    setLoadingTls(true);
    setLoadingPort(true);
    setLoadingDirectory(true);
    setLoadingBusiness(true);
    setError(null);
    setHeaderData(null);
    setTlsData(null);
    setPortData(null);
    setDirData(null);
    setBusinessData(null);
    setScanned(false);

    try {
      const [headerRes, tlsRes, portRes, dirRes, businessRes] = await Promise.all([
        fetch(`${API}/scan/header`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        }),
        fetch(`${API}/scan/tls`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        }),
        fetch(`${API}/scan/ports`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        }),
        fetch(`${API}/scan/directories`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        }),
        fetch(`${API}/scan/business`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url, jwt_token: jwtToken }),
        }),
      ]);

      const [headerJson, tlsJson, portJson, dirJson, businessJson] = await Promise.all([
        headerRes.json(),
        tlsRes.json(),
        portRes.json(),
        dirRes.json(),
        businessRes.json(),
      ]);

      setHeaderData(headerJson);
      setTlsData(tlsJson.error ? null : tlsJson);
      setPortData(portJson);
      setDirData(dirJson);
      setBusinessData(businessJson);
      setScanned(true);
    } catch (err) {
      setError("Cannot reach the scanner backend. Is Flask running on port 5000?");
    } finally {
      setLoadingHeader(false);
      setLoadingTls(false);
      setLoadingPort(false);
      setLoadingDirectory(false);
      setLoadingBusiness(false);
    }
  };

  // Clear all results
  const clearResults = () => {
    setHeaderData(null);
    setTlsData(null);
    setPortData(null);
    setDirData(null);
    setBusinessData(null);
    setScanned(false);

    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#0a0f1e] text-slate-100" style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
      <header className="border-b border-slate-800 bg-[#080d1a]/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center gap-4">
          <div className="flex items-center gap-2.5">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <polygon points="12,2 22,7 22,17 12,22 2,17 2,7" stroke="#3b82f6" strokeWidth="1.5" fill="none" />
              <polygon points="12,6 18,9.5 18,16.5 12,20 6,16.5 6,9.5" fill="#3b82f6" opacity="0.15" />
              <circle cx="12" cy="12" r="2.5" fill="#3b82f6" />
            </svg>
            <span className="font-bold text-sm tracking-tight text-white">E-WMEAP</span>
          </div>
          <span className="text-slate-600 text-xs hidden sm:block">
            / Enterprise Web Misconfiguration & Exposure Assessment Platform
          </span>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-10">
        {/* Hero / Input */}
        <div className="mb-12">
          <h1 className="text-3xl font-black tracking-tight text-white mb-1">
            Security Scanner
          </h1>
          <p className="text-sm text-slate-500 mb-8">
            Analyse headers, TLS, services, and exposure signals for any target URL.
          </p>

          {/* URL bar */}
          <div className="flex gap-3 items-stretch mb-4">
            <div className="flex-1 flex items-center gap-3 bg-slate-800/60 border border-slate-700/60 rounded-xl px-4
              focus-within:border-blue-500/60 focus-within:bg-slate-800 transition-all">
              <span className="text-slate-600 text-xs font-mono select-none">TARGET ›</span>
              <input
                type="text"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && scanAll()}
                className="flex-1 bg-transparent py-3.5 text-sm text-slate-100 placeholder:text-slate-600
                  font-mono focus:outline-none"
              />
            </div>
            <button
              onClick={scanAll}
              className="px-8 py-3.5 bg-blue-600 hover:bg-blue-500 active:scale-95
                text-white text-sm font-bold rounded-xl transition-all
                shadow-[0_0_20px_rgba(59,130,246,0.3)] hover:shadow-[0_0_28px_rgba(59,130,246,0.5)]"
            >
              Scan All
            </button>
            <button
              onClick={clearResults}
              className="px-4 py-3.5 bg-slate-700 hover:bg-slate-600 active:scale-95
                text-white text-sm font-bold rounded-xl transition-all"
            >
              Clear
            </button>
          </div>

          {/* Individual Module Buttons */}
          <div className="flex gap-3 flex-wrap">
            <button
              onClick={scanHeader}
              disabled={loadingHeader}
              className="px-5 py-2 bg-emerald-600/80 hover:bg-emerald-500 active:scale-95
                text-white text-xs font-bold rounded-lg transition-all
                disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loadingHeader ? "Scanning..." : "📋 Header Scanner"}
            </button>
            <button
              onClick={scanTls}
              disabled={loadingTls}
              className="px-5 py-2 bg-purple-600/80 hover:bg-purple-500 active:scale-95
                text-white text-xs font-bold rounded-lg transition-all
                disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loadingTls ? "Scanning..." : "🔒 TLS Scanner"}
            </button>
            <button
              onClick={scanPorts}
              disabled={loadingPort}
              className="px-5 py-2 bg-cyan-600/80 hover:bg-cyan-500 active:scale-95
                text-white text-xs font-bold rounded-lg transition-all
                disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loadingPort ? "Scanning..." : "🌐 Port Scanner"}
            </button>
            <button
              onClick={scanDirectories}
              disabled={loadingDirectory}
              className="px-5 py-2 bg-yellow-600/80 hover:bg-yellow-500 active:scale-95
                text-white text-xs font-bold rounded-lg transition-all
                disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loadingDirectory ? "Scanning..." : "📁 Directory Scanner"}
            </button>
            <div className="flex gap-3 items-center mt-3">
              <span className="text-slate-600 text-xs font-mono select-none flex-shrink-0">JWT TOKEN (optional) ›</span>
              <input
                type="text"
                placeholder="eyJhbGc... (paste your JWT for deeper testing)"
                value={jwtToken}
                onChange={(e) => setJwtToken(e.target.value)}
                className="flex-1 bg-slate-800/40 border border-slate-700/40 rounded-lg px-3 py-2
       text-xs text-slate-300 placeholder:text-slate-600 font-mono focus:outline-none
       focus:border-purple-500/50"
              />
              <button
                onClick={scanBusiness}
                disabled={loadingBusiness}
                className="px-5 py-2 bg-cyan-600/80 hover:bg-cyan-500 text-white text-xs
       font-bold rounded-lg transition-all disabled:opacity-40"
              >
                {loadingBusiness ? "Scanning..." : "⚙ Business Logic"}
              </button>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="mt-4 flex items-center gap-3 bg-red-950/50 border border-red-800/50 text-red-300
              text-xs rounded-lg px-4 py-3">
              <span className="text-red-500">✕</span>
              {error}
            </div>
          )}

          {/* Status Indicator */}
          {scanned && !loadingHeader && !loadingTls && !loadingPort && !loadingDirectory && (
            <div className="mt-4 flex items-center gap-2 text-xs text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Scan complete
            </div>
          )}
        </div>

        {/* Module Results */}
        <HeaderScanner
          data={headerData}
          tlsData={tlsData}
          loading={loadingHeader}
        />

        <PortScanner
          data={portData}
          loading={loadingPort}
        />
        <DirectoryScanner
          data={dirData}
          loading={loadingDirectory}
        />
        <BusinessLogicScanner
          data={businessData}
          loading={loadingBusiness}
        />
      </main>
    </div>
  );
}

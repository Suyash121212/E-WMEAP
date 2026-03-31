// components/modules/PortScanner.jsx
import { useState } from "react";
import { SeverityBadge } from "../ui/SeverityBadge";

function CVEDisplay({ cve_data }) {
  if (!cve_data || cve_data.total_cves === 0) {
    return (
      <div className="mt-3 bg-green-950/30 border border-green-800/50 rounded-lg p-3">
        <p className="text-xs text-green-300">✓ No known CVEs found for this service</p>
      </div>
    );
  }
  
  return (
    <div className="mt-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-red-400">
          ⚠️ {cve_data.total_cves} Known Vulnerabilities
        </span>
        {cve_data.has_exploit && (
          <span className="text-[10px] px-2 py-0.5 bg-purple-900/50 text-purple-300 rounded-full">
            💣 Exploit Available
          </span>
        )}
        {cve_data.has_metasploit && (
          <span className="text-[10px] px-2 py-0.5 bg-red-900/50 text-red-300 rounded-full">
            🎯 Metasploit Module
          </span>
        )}
      </div>
      
      {cve_data.cves && cve_data.cves.map((cve, idx) => (
        <div key={idx} className="bg-slate-800/40 rounded p-3 border border-slate-700/40">
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono text-sm font-bold text-red-400">{cve.id}</span>
            <div className="flex items-center gap-2">
              <span className={`text-xs px-2 py-0.5 rounded font-mono ${
                cve.cvss_score >= 9.0 ? "bg-red-900/50 text-red-300" :
                cve.cvss_score >= 7.0 ? "bg-orange-900/50 text-orange-300" :
                cve.cvss_score >= 4.0 ? "bg-yellow-900/50 text-yellow-300" :
                "bg-blue-900/50 text-blue-300"
              }`}>
                CVSS {cve.cvss_score}
              </span>
              <span className="text-[10px] text-slate-500">{cve.cvss_severity}</span>
            </div>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">{cve.description}</p>
          {cve.has_exploit && (
            <div className="mt-2 flex items-center gap-2">
              <span className="text-[10px] text-purple-400">⚡ Proof of Concept available</span>
            </div>
          )}
          {cve.source && (
            <div className="mt-2 text-[10px] text-slate-500">
              Source: {cve.source}
            </div>
          )}
        </div>
      ))}
      
      {cve_data.display_message && (
        <div className="mt-2 text-[10px] text-cyan-400 font-mono">
          {cve_data.display_message}
        </div>
      )}
    </div>
  );
}

function DangerousPortWarning({ port }) {
  if (!port.dangerous_info) return null;
  
  return (
    <div className="bg-red-950/30 border-l-4 border-red-500 rounded-lg p-3 mt-2">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-red-400 font-bold text-xs uppercase tracking-widest">
          ⚠️ CRITICAL WARNING
        </span>
        <SeverityBadge level={port.dangerous_info.risk} />
      </div>
      <p className="text-xs text-red-300">{port.dangerous_info.reason}</p>
      {port.no_auth_risk && (
        <p className="text-xs text-yellow-400 mt-2">
          🔴 DANGEROUS COMBINATION: Database port exposed without authentication!
        </p>
      )}
      <p className="text-xs text-slate-400 mt-2">
        Recommended Action: Restrict access to this port immediately using firewall rules
        and ensure proper authentication is configured.
      </p>
    </div>
  );
}

function ServiceDetails({ port }) {
  return (
    <div>
      <h4 className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
        Service Details
      </h4>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <span className="text-slate-500">Service:</span>
          <span className="ml-2 text-slate-300 font-mono">
            {port.service || port.product || "Unknown"}
          </span>
        </div>
        <div>
          <span className="text-slate-500">Version:</span>
          <span className="ml-2 text-slate-300 font-mono">
            {port.version || "Unknown"}
          </span>
        </div>
        <div>
          <span className="text-slate-500">Protocol:</span>
          <span className="ml-2 text-slate-300">{port.protocol}</span>
        </div>
        {port.extrainfo && (
          <div className="col-span-2">
            <span className="text-slate-500">Extra Info:</span>
            <span className="ml-2 text-slate-300 text-[11px]">{port.extrainfo}</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default function PortScanner({ data, loading }) {
  const [expandedPort, setExpandedPort] = useState(null);
  
  if (loading) {
    return (
      <section className="mb-8 animate-pulse">
        <div className="h-6 w-48 bg-slate-700 rounded mb-4" />
        <div className="bg-slate-800/50 rounded-xl h-96 border border-slate-700/40" />
      </section>
    );
  }
  
  if (!data) return null;
  
  if (data.error) {
    return (
      <section className="mb-8">
        <div className="flex items-center gap-3 mb-5">
          <div className="w-1 h-6 rounded-full bg-red-500" />
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
            Port & Service Analysis
          </h2>
        </div>
        <div className="bg-red-950/30 border border-red-800/50 rounded-lg p-4 text-red-300 text-sm">
          <span className="font-bold">Error:</span> {data.error}
          {data.error?.includes("nmap") && (
            <div className="mt-2 text-xs text-yellow-400">
              💡 Tip: Install nmap with: sudo apt-get install nmap (Linux) or brew install nmap (macOS)
            </div>
          )}
        </div>
      </section>
    );
  }
  
  const { 
    open_ports = [], 
    total_open = 0, 
    dangerous_ports = [], 
    risk_score = 0, 
    risk_level = "None",
    scan_mode = "full",
    target = "Unknown",
    scanned_ports = []
  } = data;
  
  const getRiskColor = () => {
    if (risk_score >= 80) return "text-red-500";
    if (risk_score >= 60) return "text-orange-500";
    if (risk_score >= 30) return "text-yellow-500";
    if (risk_score > 0) return "text-blue-500";
    return "text-green-500";
  };
  
  const getRiskBgColor = () => {
    if (risk_score >= 80) return "bg-red-950/30 border-red-800";
    if (risk_score >= 60) return "bg-orange-950/30 border-orange-800";
    if (risk_score >= 30) return "bg-yellow-950/30 border-yellow-800";
    if (risk_score > 0) return "bg-blue-950/30 border-blue-800";
    return "bg-green-950/30 border-green-800";
  };
  
  return (
    <section className="mb-8">
      <div className="flex items-center gap-3 mb-5">
        <div className="w-1 h-6 rounded-full bg-cyan-500" />
        <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
          Port & Service Analysis
        </h2>
        <span className="ml-auto text-xs text-slate-500">
          {scan_mode === "fast" ? "⚡ Fast Mode" : "🔍 Full Mode (with CVE enrichment)"}
        </span>
      </div>
      
      {/* Summary Cards */}
      <div className="flex flex-wrap gap-6 mb-6">
        <div className="flex flex-col items-center gap-1">
          <div className={`text-3xl font-black font-mono ${getRiskColor()}`}>
            {risk_score}/100
          </div>
          <div className="text-xs text-slate-500 uppercase tracking-widest">Risk Score</div>
          <SeverityBadge level={risk_level} />
        </div>
        
        <div className="flex gap-3">
          <div className="px-4 py-2 rounded-lg bg-slate-800/60 border border-slate-700/50">
            <div className="text-2xl font-black font-mono text-cyan-400">{total_open}</div>
            <div className="text-[10px] uppercase text-slate-500">Open Ports</div>
          </div>
          <div className="px-4 py-2 rounded-lg bg-slate-800/60 border border-slate-700/50">
            <div className="text-2xl font-black font-mono text-red-400">{dangerous_ports?.length || 0}</div>
            <div className="text-[10px] uppercase text-slate-500">Dangerous Ports</div>
          </div>
        </div>
        
        {/* Scan Info */}
        <div className="ml-auto text-right">
          <div className="text-xs text-slate-500">Target</div>
          <div className="text-xs font-mono text-cyan-400">{target}</div>
          <div className="text-[10px] text-slate-600 mt-1">
            Scanned: {scanned_ports?.length || 0} ports
          </div>
        </div>
      </div>
      
      {/* Overall Risk Summary */}
      {risk_level !== "None" && (
        <div className={`mb-6 p-4 rounded-lg border ${getRiskBgColor()}`}>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm font-bold">Overall Security Assessment</span>
            <SeverityBadge level={risk_level} />
          </div>
          <p className="text-sm text-slate-300">
            {risk_level === "Critical" && "⚠️ CRITICAL: Multiple high-risk ports exposed with known vulnerabilities. Immediate action required!"}
            {risk_level === "High" && "🔴 HIGH: Dangerous ports or critical vulnerabilities detected. Prioritize remediation."}
            {risk_level === "Medium" && "🟡 MEDIUM: Some security concerns found. Review and address findings."}
            {risk_level === "Low" && "🟢 LOW: Minor security issues detected."}
          </p>
        </div>
      )}
      
      {/* Port List */}
      {open_ports.length > 0 ? (
        <div className="space-y-3">
          {open_ports.map((port, idx) => (
            <div 
              key={idx} 
              className={`rounded-lg border ${
                port.dangerous ? "border-red-800/50 bg-red-950/10" : 
                port.cve_enrichment?.highest_severity === "Critical" ? "border-red-800/50 bg-red-950/5" :
                port.cve_enrichment?.highest_severity === "High" ? "border-orange-800/50 bg-orange-950/5" :
                "border-slate-700/50 bg-slate-800/20"
              } overflow-hidden transition-all`}
            >
              {/* Port Header */}
              <div 
                className="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-slate-700/20 transition-colors"
                onClick={() => setExpandedPort(expandedPort === idx ? null : idx)}
              >
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="font-mono font-bold text-lg text-cyan-400">
                    {port.port}/{port.protocol}
                  </span>
                  <span className="text-sm text-slate-300">
                    {port.service || port.product || "Unknown"}
                  </span>
                  {port.version && port.version !== "Unknown" && (
                    <span className="text-xs font-mono text-slate-500 bg-slate-800/50 px-2 py-0.5 rounded">
                      v{port.version}
                    </span>
                  )}
                  {port.dangerous && (
                    <span className="text-xs px-2 py-0.5 bg-red-900/60 text-red-300 rounded-full font-bold">
                      {port.dangerous_info?.risk || "DANGEROUS"}
                    </span>
                  )}
                  {port.cve_enrichment?.highest_severity === "Critical" && (
                    <span className="text-xs px-2 py-0.5 bg-red-900/60 text-red-300 rounded-full">
                      CRITICAL CVE
                    </span>
                  )}
                  {port.cve_enrichment?.has_exploit && (
                    <span className="text-xs px-2 py-0.5 bg-purple-900/60 text-purple-300 rounded-full">
                      💣 EXPLOIT
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {port.cve_enrichment?.total_cves > 0 && (
                    <span className="text-xs text-red-400">
                      {port.cve_enrichment.total_cves} CVEs
                    </span>
                  )}
                  <span className="text-slate-500 text-xl">
                    {expandedPort === idx ? "▾" : "▸"}
                  </span>
                </div>
              </div>
              
              {/* Expanded Details */}
              {expandedPort === idx && (
                <div className="px-4 pb-4 pt-2 border-t border-slate-700/30 space-y-4">
                  {/* Display Message from PDF */}
                  {port.display_message && (
                    <div className="bg-cyan-950/30 border border-cyan-800/50 rounded-lg p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-cyan-400 text-xs font-bold">🔍 SCAN RESULT</span>
                      </div>
                      <p className="text-sm text-cyan-300 font-mono">
                        {port.display_message}
                      </p>
                    </div>
                  )}
                  
                  {/* Service Details */}
                  <ServiceDetails port={port} />
                  
                  {/* Dangerous Port Warning */}
                  <DangerousPortWarning port={port} />
                  
                  {/* CVE Enrichment */}
                  {port.cve_enrichment && (
                    <CVEDisplay cve_data={port.cve_enrichment} />
                  )}
                  
                  {/* No CVE Data */}
                  {(!port.cve_enrichment || port.cve_enrichment.total_cves === 0) && port.version && port.version !== "Unknown" && (
                    <div className="bg-green-950/30 border border-green-800/50 rounded-lg p-3">
                      <p className="text-xs text-green-300">
                        ✓ No known CVEs found for {port.service || port.product} version {port.version}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-emerald-950/30 border border-emerald-800/50 rounded-lg p-4 text-center">
          <div className="text-3xl mb-2">🔒</div>
          <p className="text-emerald-300 text-sm font-medium">No open ports detected</p>
          <p className="text-xs text-slate-500 mt-1">
            All scanned ports are filtered or closed. This indicates good network security posture.
          </p>
        </div>
      )}
      
      {/* Dangerous Ports Summary */}
      {dangerous_ports && dangerous_ports.length > 0 && (
        <div className="mt-6 p-4 bg-red-950/30 border border-red-800/50 rounded-lg">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-red-400 font-bold text-sm uppercase tracking-widest">
              ⚠️ CRITICAL SECURITY ISSUES
            </span>
            <span className="text-xs text-red-300">{dangerous_ports.length} dangerous port(s) exposed</span>
          </div>
          <p className="text-sm text-slate-300">
            The following services should NOT be publicly accessible:
          </p>
          <div className="flex flex-wrap gap-2 mt-2">
            {dangerous_ports.map((port, idx) => (
              <span key={idx} className="text-xs bg-red-900/40 text-red-300 px-2 py-1 rounded">
                Port {port.port} - {port.dangerous_info?.service}
              </span>
            ))}
          </div>
          <p className="text-xs text-slate-400 mt-3">
            Recommended Action: Implement firewall rules to restrict access to these ports.
          </p>
        </div>
      )}
    </section>
  );
}

# backend/modules/risk_engine/engine.py
# Module 8 — Risk Engine Orchestrator
# Aggregates all module results → CVSS scores → chains → threat intel → overall grade

import time
from datetime import datetime
from urllib.parse import urlparse

from .cvss_scorer  import score_findings_batch, calculate_cvss
from .chains       import detect_chains
from .threat_intel import enrich_threat_intel

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, "Info": 5}

LETTER_GRADES = [
    (95, "A+"), (85, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")
]

def _letter_grade(score: int) -> str:
    for threshold, grade in LETTER_GRADES:
        if score >= threshold:
            return grade
    return "F"


def _extract_all_findings(scan_results: dict) -> list:
    """
    Flatten all findings from all modules into a unified list.
    Each finding gets: module, type, severity, description, cvss.
    """
    findings = []

    # ── Header scanner ────────────────────────────────────────────────────
    for f in scan_results.get("headers", {}).get("findings", []):
        if f.get("severity", "None") == "None":
            continue
        findings.append({
            "module":      "Headers",
            "type":        f.get("header", "Header"),
            "severity":    f.get("severity"),
            "description": f.get("impact", ""),
            "recommendation": f.get("recommendation", ""),
            "raw":         f,
        })

    # ── TLS ───────────────────────────────────────────────────────────────
    tls = scan_results.get("tls", {})
    if tls.get("grade") in ("C", "D", "F"):
        findings.append({
            "module":      "TLS",
            "type":        f"TLS_Grade_{tls.get('grade', 'F')}",
            "severity":    "High" if tls.get("grade") in ("C", "D") else "Critical",
            "description": f"TLS grade {tls.get('grade')} — {', '.join(tls.get('issues', [])[:2])}",
            "recommendation": "Upgrade TLS to 1.3. Enable HSTS with preload.",
            "raw":         tls,
        })
    for issue in tls.get("issues", []):
        findings.append({
            "module":      "TLS",
            "type":        "TLS_Issue",
            "severity":    "Medium",
            "description": issue,
            "recommendation": "Address TLS configuration issues.",
            "raw":         {"issue": issue},
        })

    # ── Port scanner ──────────────────────────────────────────────────────
    for port_info in scan_results.get("ports", {}).get("open_ports", []):
        sev = "Critical" if port_info.get("port") in (3306, 5432, 27017, 6379, 2375) else "High"
        findings.append({
            "module":      "Ports",
            "type":        f"Port_{port_info.get('service', 'Service')}_Exposed",
            "severity":    sev,
            "description": f"Port {port_info.get('port')} ({port_info.get('service')}) is internet-accessible",
            "recommendation": f"Restrict port {port_info.get('port')} to internal network only.",
            "raw":         port_info,
        })

    # ── Directory scanner ─────────────────────────────────────────────────
    for f in scan_results.get("directories", {}).get("findings", []):
        if f.get("severity", "None") in ("None", "Low"):
            continue
        findings.append({
            "module":      "Directories",
            "type":        _dir_type(f),
            "severity":    f.get("severity"),
            "description": f"{f.get('path')} — {f.get('description', '')}",
            "recommendation": f.get("recommendation", "Restrict access to this path."),
            "poc":         f.get("poc"),
            "raw":         f,
        })

    # ── Business logic (CORS / JWT / GraphQL) ────────────────────────────
    biz = scan_results.get("business", {})
    for sub in ("cors", "jwt", "graphql"):
        for f in biz.get(sub, {}).get("findings", []):
            if not f.get("exploitable"):
                continue
            findings.append({
                "module":      f"Business ({sub.upper()})",
                "type":        f.get("test", f"Business_{sub}"),
                "severity":    f.get("severity"),
                "description": f.get("description", ""),
                "recommendation": "",
                "poc":         f.get("poc"),
                "technique":   f.get("technique"),
                "raw":         f,
            })

    # ── Secrets ───────────────────────────────────────────────────────────
    web_secrets = scan_results.get("secrets", {}).get("web", {})
    for file_f in web_secrets.get("findings", []):
        if not file_f.get("accessible"):
            continue
        for sec in file_f.get("secrets", []):
            findings.append({
                "module":      "Secrets (Web)",
                "type":        f"Secret_{sec.get('type', 'Generic').replace(' ', '_')}",
                "severity":    sec.get("severity", "High"),
                "description": f"{sec.get('type')} found in {file_f.get('path')}",
                "recommendation": "Rotate credential immediately. Remove from web-accessible files.",
                "raw":         sec,
            })
        if not file_f.get("secrets") and file_f.get("accessible"):
            findings.append({
                "module":      "Secrets (Web)",
                "type":        "Sensitive_File_Exposed",
                "severity":    file_f.get("severity"),
                "description": f"Sensitive file {file_f.get('path')} is accessible",
                "recommendation": "Remove file from web root.",
                "raw":         file_f,
            })

    # GitHub secrets
    for repo_f in scan_results.get("secrets", {}).get("github", {}).get("findings", []):
        for sec in repo_f.get("secrets", []):
            findings.append({
                "module":      "Secrets (GitHub)",
                "type":        f"Secret_{sec.get('type', 'Generic').replace(' ', '_')}",
                "severity":    sec.get("severity", "High"),
                "description": f"{sec.get('type')} in {repo_f.get('repo')}/{sec.get('file', '')}",
                "recommendation": "Rotate credential. Remove from git history with git-filter-repo.",
                "raw":         sec,
            })

    # ── Cloud ─────────────────────────────────────────────────────────────
    cloud = scan_results.get("cloud", {})
    for f in cloud.get("s3", {}).get("findings", []):
        findings.append({
            "module":      "Cloud (S3)",
            "type":        "S3_Public_Read" if f.get("public_read") else "S3_Exists",
            "severity":    f.get("severity"),
            "description": f.get("finding", ""),
            "recommendation": "Enable S3 Block Public Access.",
            "raw":         f,
        })
    for f in cloud.get("subdomains", {}).get("takeover_findings", []):
        if not f.get("exploitable"):
            continue
        findings.append({
            "module":      "Cloud (Subdomains)",
            "type":        "Subdomain_Takeover",
            "severity":    f.get("severity"),
            "description": f.get("description", ""),
            "recommendation": "Remove dangling CNAME records.",
            "raw":         f,
        })
    for f in cloud.get("services", {}).get("findings", []):
        findings.append({
            "module":      "Cloud (Services)",
            "type":        f"{f.get('verifier_key', 'Service').title().replace('_', '')}_Exposed",
            "severity":    f.get("severity"),
            "description": f.get("description", ""),
            "recommendation": f.get("remediation", ""),
            "raw":         f,
        })

    return findings


def _dir_type(f: dict) -> str:
    path = f.get("path", "")
    cat  = f.get("category", "")
    if ".git" in path:        return "Git_Exposed"
    if ".env" in path:        return "Env_File_Exposed"
    if "admin" in path:       return "Admin_Panel_Exposed"
    if "backup" in path:      return "Backup_Exposed"
    if "phpmyadmin" in path:  return "phpMyAdmin_Exposed"
    if "graphql" in path:     return "GraphQL_Introspection"
    if cat == "api":          return "API_Endpoint_Exposed"
    return f"Directory_{cat.title()}"


def _compute_overall_score(findings: list, chains: list) -> int:
    """
    Compute 0-100 security score.
    Start at 100, deduct based on findings and chains.
    """
    deductions = {
        "Critical": 20,
        "High":     10,
        "Medium":   5,
        "Low":      2,
    }
    total = 100
    for f in findings:
        total -= deductions.get(f.get("severity", "None"), 0)
    for c in chains:
        total -= deductions.get(c.get("severity", "None"), 0) * 1.5

    return max(0, min(100, int(total)))


def _build_remediation_priority(findings: list, chains: list) -> list:
    """Sort all findings + chains by CVSS score descending."""
    all_items = []
    for f in findings:
        all_items.append({
            "title":       f.get("type", "").replace("_", " "),
            "module":      f.get("module", ""),
            "severity":    f.get("severity", "Low"),
            "cvss_score":  f.get("cvss", {}).get("score", 0),
            "description": f.get("description", ""),
            "recommendation": f.get("recommendation", ""),
            "is_chain":    False,
        })
    for c in chains:
        all_items.append({
            "title":       c.get("name", ""),
            "module":      "Vulnerability Chain",
            "severity":    c.get("severity", "Critical"),
            "cvss_score":  c.get("cvss", {}).get("score", 0),
            "description": c.get("description", ""),
            "recommendation": c.get("remediation", ""),
            "is_chain":    True,
        })
    return sorted(all_items, key=lambda x: x["cvss_score"], reverse=True)[:20]


# ── Main entry point ──────────────────────────────────────────────────────────

def build_risk_report(scan_results: dict, target_url: str, scan_id: str = None) -> dict:
    """
    Aggregate all module results into a unified risk report with:
    - CVSS-scored findings
    - Vulnerability chains
    - Threat intelligence
    - Overall security score + grade
    - Remediation priority list
    """
    parsed  = urlparse(target_url)
    domain  = parsed.netloc or target_url
    domain  = domain.split(":")[0].lstrip("www.")

    scan_ts = datetime.utcnow().isoformat() + "Z"

    # 1 — Extract and flatten all findings
    raw_findings = _extract_all_findings(scan_results)

    # 2 — CVSS score each finding
    scored_findings = score_findings_batch(raw_findings)

    # 3 — Detect vulnerability chains
    chains = detect_chains(scan_results)

    # 4 — Threat intelligence enrichment
    threat_intel = enrich_threat_intel(domain)

    # 5 — Overall score
    score = _compute_overall_score(scored_findings, chains)
    grade = _letter_grade(score)

    # 6 — Severity distribution
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in scored_findings:
        sev = f.get("severity", "Info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    for c in chains:
        sev_counts["Critical"] = sev_counts.get("Critical", 0) + 1

    # 7 — Remediation priority
    priority_list = _build_remediation_priority(scored_findings, chains)

    # 8 — Module summary
    module_summary = _build_module_summary(scan_results, scored_findings)

    # 9 — Top 3 critical for executive summary
    critical_top3 = [
        f for f in scored_findings
        if f.get("severity") in ("Critical", "High")
    ][:3]

    return {
        "scan_id":          scan_id or f"scan_{int(time.time())}",
        "target":           target_url,
        "domain":           domain,
        "scan_timestamp":   scan_ts,
        "overall_score":    score,
        "overall_grade":    grade,
        "severity_counts":  sev_counts,
        "total_findings":   len(scored_findings),
        "total_chains":     len(chains),
        "findings":         scored_findings,
        "chains":           chains,
        "priority_list":    priority_list,
        "module_summary":   module_summary,
        "threat_intel":     threat_intel,
        "executive_summary": _build_exec_summary(target_url, score, grade, critical_top3, chains, sev_counts),
    }


def _build_module_summary(scan_results: dict, findings: list) -> list:
    modules = [
        ("Headers",           "header",     scan_results.get("headers", {})),
        ("TLS/SSL",           "tls",        scan_results.get("tls", {})),
        ("Port Scanner",      "ports",      scan_results.get("ports", {})),
        ("Directory Scanner", "directories",scan_results.get("directories", {})),
        ("Business Logic",    "business",   scan_results.get("business", {})),
        ("Secrets",           "secrets",    scan_results.get("secrets", {})),
        ("Cloud",             "cloud",      scan_results.get("cloud", {})),
    ]
    result = []
    for name, key, data in modules:
        if not data:
            continue
        module_findings = [f for f in findings if key in f.get("module", "").lower()]
        sev = data.get("overall_severity", "None")
        if not sev or sev == "None":
            top = min(module_findings, key=lambda f: SEV_ORDER.get(f.get("severity", "None"), 99), default=None)
            sev = top["severity"] if top else "None"
        result.append({
            "name":     name,
            "key":      key,
            "severity": sev,
            "count":    len(module_findings),
            "summary":  data.get("summary", data.get("risk_summary", "")),
        })
    return result


def _build_exec_summary(target: str, score: int, grade: str, top3: list, chains: list, sev_counts: dict) -> dict:
    risk_level = (
        "Critical Risk" if score < 40 else
        "High Risk"     if score < 60 else
        "Medium Risk"   if score < 75 else
        "Low Risk"      if score < 90 else
        "Minimal Risk"
    )

    immediate_actions = []
    for f in top3:
        rec = f.get("recommendation", "")
        if rec:
            immediate_actions.append(rec)
    for c in chains[:2]:
        immediate_actions.append(c.get("remediation", ""))

    return {
        "overall_risk_level": risk_level,
        "score":              score,
        "grade":              grade,
        "critical_count":     sev_counts.get("Critical", 0),
        "high_count":         sev_counts.get("High", 0),
        "chain_count":        len(chains),
        "top_findings":       [
            {
                "title":       f.get("type", "").replace("_", " "),
                "severity":    f.get("severity"),
                "description": f.get("description", ""),
                "cvss_score":  f.get("cvss", {}).get("score", 0),
            }
            for f in top3
        ],
        "immediate_actions": list(dict.fromkeys(a for a in immediate_actions if a))[:5],
        "narrative": _risk_narrative(score, grade, sev_counts, chains),
    }


def _risk_narrative(score: int, grade: str, sev_counts: dict, chains: list) -> str:
    c = sev_counts.get("Critical", 0)
    h = sev_counts.get("High", 0)
    chains_count = len(chains)

    if score < 40:
        return (
            f"The target has a security grade of {grade} ({score}/100) indicating critical security posture. "
            f"{c} critical and {h} high-severity vulnerabilities were found. "
            + (f"{chains_count} vulnerability chain(s) were confirmed — individual weaknesses combine into more severe attack paths. " if chains_count else "")
            + "Immediate remediation is required before this system handles sensitive data."
        )
    elif score < 65:
        return (
            f"The target has a security grade of {grade} ({score}/100) with significant findings that require attention. "
            f"{c + h} high-impact vulnerabilities detected. "
            + (f"{chains_count} vulnerability chain(s) identified. " if chains_count else "")
            + "A remediation plan should be implemented within 30 days."
        )
    elif score < 85:
        return (
            f"The target has a security grade of {grade} ({score}/100) with moderate risk. "
            "Some security controls are in place but gaps exist. Schedule remediation within 90 days."
        )
    else:
        return (
            f"The target has a security grade of {grade} ({score}/100) indicating good security posture. "
            "Minor improvements recommended to achieve best-practice configuration."
        )
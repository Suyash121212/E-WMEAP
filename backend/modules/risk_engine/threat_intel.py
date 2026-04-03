# backend/modules/risk_engine/threat_intel.py
# Module 8.3 — Threat Intelligence Enrichment
# APIs: Shodan, AlienVault OTX, AbuseIPDB — all free tiers

import os
import socket
import requests

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "E-WMEAP-Scanner/1.0"})

SHODAN_KEY    = os.environ.get("SHODAN_API_KEY", "")
OTX_KEY       = os.environ.get("OTX_API_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")


def _resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


# ── Shodan ────────────────────────────────────────────────────────────────────

def _query_shodan(ip: str) -> dict:
    if not SHODAN_KEY:
        return {"available": False, "reason": "SHODAN_API_KEY not set"}
    try:
        r = SESSION.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_KEY},
            timeout=10,
        )
        if r.status_code == 404:
            return {"available": True, "indexed": False, "ip": ip}
        if r.status_code == 401:
            return {"available": False, "reason": "Invalid Shodan API key"}
        if r.status_code != 200:
            return {"available": False, "reason": f"Shodan returned {r.status_code}"}

        data = r.json()
        ports    = data.get("ports", [])
        hostnames= data.get("hostnames", [])
        org      = data.get("org", "Unknown")
        country  = data.get("country_name", "Unknown")
        vulns    = list(data.get("vulns", {}).keys())
        tags     = data.get("tags", [])
        last_seen= data.get("last_update", "Unknown")

        return {
            "available":   True,
            "indexed":     True,
            "ip":          ip,
            "org":         org,
            "country":     country,
            "ports":       ports,
            "hostnames":   hostnames,
            "vulns":       vulns[:10],
            "tags":        tags,
            "last_seen":   last_seen,
            "risk_note":   (
                "⚠ Target is already indexed by Shodan — attackers have automatic awareness of open ports."
                if ports else
                "Target found in Shodan but no open ports indexed."
            ),
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


# ── AlienVault OTX ────────────────────────────────────────────────────────────

def _query_otx(domain: str, ip: str = None) -> dict:
    if not OTX_KEY:
        return {"available": False, "reason": "OTX_API_KEY not set"}

    headers = {"X-OTX-API-KEY": OTX_KEY}
    results = {"available": True, "domain": domain}

    try:
        # Domain intelligence
        r = SESSION.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            data  = r.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            results["pulse_count"]     = pulse_count
            results["threat_score"]    = data.get("alexa", "Unknown")
            results["validation"]      = data.get("validation", [])
            results["malware_families"]= [
                p.get("name", "") for p in
                data.get("pulse_info", {}).get("pulses", [])[:5]
            ]
            results["is_malicious"] = pulse_count > 0
            results["risk_note"] = (
                f"⚠ Domain appears in {pulse_count} OTX threat intelligence pulse(s) — may be associated with malicious activity."
                if pulse_count > 0 else
                "Domain not found in AlienVault OTX threat feeds."
            )

        # IP reputation if available
        if ip:
            r2 = SESSION.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers=headers, timeout=10,
            )
            if r2.status_code == 200:
                d2 = r2.json()
                results["ip_pulse_count"] = d2.get("pulse_info", {}).get("count", 0)
                results["ip_reputation"]  = "malicious" if results["ip_pulse_count"] > 0 else "clean"

    except Exception as e:
        results["error"] = str(e)

    return results


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def _query_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"available": False, "reason": "ABUSEIPDB_API_KEY not set"}
    try:
        r = SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        if r.status_code != 200:
            return {"available": False, "reason": f"AbuseIPDB returned {r.status_code}"}

        data  = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        isp   = data.get("isp", "Unknown")
        usage = data.get("usageType", "Unknown")
        country = data.get("countryCode", "Unknown")
        domain  = data.get("domain", "Unknown")

        return {
            "available":       True,
            "ip":              ip,
            "abuse_score":     score,
            "total_reports":   reports,
            "isp":             isp,
            "usage_type":      usage,
            "country":         country,
            "domain":          domain,
            "is_malicious":    score > 25,
            "risk_note": (
                f"⚠ IP has abuse confidence score of {score}% with {reports} report(s) in the last 90 days."
                if score > 25 else
                f"IP has low abuse score ({score}%). ISP: {isp}."
            ),
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


# ── Main entry point ──────────────────────────────────────────────────────────

def enrich_threat_intel(domain: str) -> dict:
    """Run all three threat intelligence APIs against target domain."""
    ip      = _resolve_ip(domain)
    shodan  = _query_shodan(ip) if ip else {"available": False, "reason": "Could not resolve IP"}
    otx     = _query_otx(domain, ip)
    abuse   = _query_abuseipdb(ip) if ip else {"available": False, "reason": "Could not resolve IP"}

    # Compute overall threat level
    threat_indicators = []
    if shodan.get("indexed") and shodan.get("vulns"):
        threat_indicators.append(f"Known CVEs indexed by Shodan: {', '.join(shodan['vulns'][:3])}")
    if otx.get("is_malicious"):
        threat_indicators.append(f"In {otx.get('pulse_count')} OTX threat pulse(s)")
    if abuse.get("is_malicious"):
        threat_indicators.append(f"AbuseIPDB score: {abuse.get('abuse_score')}%")

    threat_level = "High" if len(threat_indicators) >= 2 else "Medium" if threat_indicators else "Low"

    return {
        "domain":            domain,
        "ip":                ip,
        "threat_level":      threat_level,
        "threat_indicators": threat_indicators,
        "shodan":            shodan,
        "otx":               otx,
        "abuseipdb":         abuse,
        "api_keys_configured": {
            "shodan":    bool(SHODAN_KEY),
            "otx":       bool(OTX_KEY),
            "abuseipdb": bool(ABUSEIPDB_KEY),
        },
    }


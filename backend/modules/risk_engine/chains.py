# backend/modules/risk_engine/chains.py
# Vulnerability chaining — detects when multiple findings combine into higher risk
# Each chain rule checks for combinations across all module results

from .cvss_scorer import calculate_cvss

# ── Chain rule definitions ────────────────────────────────────────────────────
# Each rule: (chain_id, name, severity, description, impact, check_fn)

def _text_in(text: str, *keywords) -> bool:
    t = text.lower()
    return any(k.lower() in t for k in keywords)


def _has_finding(results: dict, module: str, *keywords) -> bool:
    """Check if a module has any finding matching keywords."""
    module_data = results.get(module, {})
    if not module_data:
        return False

    # Check different result structures
    findings_keys = ["findings", "takeover_findings", "secrets", "open_ports"]
    for key in findings_keys:
        items = module_data.get(key, [])
        for item in items:
            text = " ".join(str(v) for v in item.values() if isinstance(v, (str, int)))
            if _text_in(text, *keywords):
                return True

    # For nested structures (cors, jwt, graphql inside business)
    for sub_key in ("cors", "jwt", "graphql"):
        sub = module_data.get(sub_key, {})
        if sub:
            for item in sub.get("findings", []):
                text = " ".join(str(v) for v in item.values() if isinstance(v, (str, int)))
                if _text_in(text, *keywords):
                    return True

    return False


def _has_severity(results: dict, module: str, severity: str) -> bool:
    """Check if a module has any finding of given severity."""
    module_data = results.get(module, {})
    overall = module_data.get("overall_severity", "None")
    return overall in {severity, *_higher_sevs(severity)}


def _higher_sevs(sev: str) -> list:
    order = ["None", "Low", "Medium", "High", "Critical"]
    idx = order.index(sev) if sev in order else 0
    return order[idx:]


CHAIN_RULES = [

    # ── 1. CORS reflection + no HttpOnly cookie ───────────────────────────
    {
        "id":          "cors_session_hijack",
        "name":        "CORS Misconfiguration → Session Hijacking",
        "severity":    "Critical",
        "cvss_key":    "Chain_Session_Hijack",
        "description": "CORS origin reflection is exploitable AND session cookies lack HttpOnly flag. Attacker can steal authenticated session via cross-origin request.",
        "impact":      "Full account takeover — authenticated API calls readable from attacker's domain.",
        "components":  ["CORS Origin Reflection", "Session Cookie (HttpOnly=False)"],
        "check": lambda r: (
            _has_finding(r, "business", "Origin Reflection", "reflection") and
            _has_finding(r, "headers", "cookie", "httponly", "secure")
        ),
        "remediation": "Fix CORS to use explicit origin allowlist. Set all session cookies with HttpOnly=True.",
    },

    # ── 2. Subdomain takeover + CSP allows subdomains ────────────────────
    {
        "id":          "subdomain_xss_chain",
        "name":        "Subdomain Takeover → XSS via CSP Bypass",
        "severity":    "Critical",
        "cvss_key":    "Chain_XSS_Takeover",
        "description": "A subdomain is vulnerable to takeover AND the CSP policy trusts subdomains. Attacker claims the subdomain, hosts malicious scripts, CSP allows them.",
        "impact":      "XSS on any page of the main domain via trusted-but-compromised subdomain.",
        "components":  ["Subdomain Takeover", "Weak CSP (subdomain trust)"],
        "check": lambda r: (
            _has_finding(r, "cloud", "takeover", "exploitable") and
            _has_finding(r, "headers", "unsafe-inline", "csp", "wildcard")
        ),
        "remediation": "Claim or remove dangling DNS records. Restrict CSP to explicit origins only.",
    },

    # ── 3. Exposed .git + secrets in code ────────────────────────────────
    {
        "id":          "git_secret_exposure",
        "name":        "Exposed .git → Source Code + Secret Extraction",
        "severity":    "Critical",
        "cvss_key":    "Chain_Data_Exfil",
        "description": "The .git directory is accessible AND secret patterns were found in the codebase. Source code can be reconstructed and secrets extracted.",
        "impact":      "Full source code + production credentials exposed to any attacker.",
        "components":  ["/.git Exposed", "Secrets in Codebase"],
        "check": lambda r: (
            _has_finding(r, "directories", "git", "source_control") and
            (r.get("secrets", {}).get("total_secrets", 0) > 0 or
             _has_finding(r, "directories", "git_reconstruction"))
        ),
        "remediation": "Block /.git access via server config. Rotate all secrets found in code immediately.",
    },

    # ── 4. Open database port + no auth ──────────────────────────────────
    {
        "id":          "open_db_no_auth",
        "name":        "Exposed Database Port → Unauthenticated Data Access",
        "severity":    "Critical",
        "cvss_key":    "Chain_Data_Exfil",
        "description": "A database service port (MySQL/Postgres/MongoDB/Redis) is internet-accessible. Default configurations often require no authentication.",
        "impact":      "Complete database dump without credentials.",
        "components":  ["Open Database Port", "No Authentication"],
        "check": lambda r: _has_finding(r, "ports", "3306", "5432", "27017", "6379", "database", "mysql", "postgres", "mongodb", "redis"),
        "remediation": "Bind database ports to localhost only. Use firewall rules. Enable authentication.",
    },

    # ── 5. JWT alg:none + admin endpoint ─────────────────────────────────
    {
        "id":          "jwt_privilege_escalation",
        "name":        "JWT alg:none → Privilege Escalation to Admin",
        "severity":    "Critical",
        "cvss_key":    "Chain_RCE",
        "description": "JWT authentication accepts alg:none tokens AND an admin endpoint is accessible. Attacker forges admin JWT and accesses privileged functionality.",
        "impact":      "Full administrative access without credentials.",
        "components":  ["JWT alg:none accepted", "Admin endpoint accessible"],
        "check": lambda r: (
            _has_finding(r, "business", "alg", "none", "algorithm confusion") and
            _has_finding(r, "directories", "admin", "/admin", "administrator")
        ),
        "remediation": "Reject alg:none tokens. Restrict admin endpoints by IP and require MFA.",
    },

    # ── 6. Docker API + no TLS ────────────────────────────────────────────
    {
        "id":          "docker_host_takeover",
        "name":        "Unauthenticated Docker API → Full Host Takeover",
        "severity":    "Critical",
        "cvss_key":    "Chain_RCE",
        "description": "Docker daemon API is accessible without TLS/authentication. Combined with default capabilities, this allows mounting host filesystem.",
        "impact":      "Complete host OS compromise — read/write any file, run any process.",
        "components":  ["Docker API Exposed (port 2375)", "No TLS Authentication"],
        "check": lambda r: _has_finding(r, "cloud", "docker", "2375", "Docker API"),
        "remediation": "Disable TCP Docker API or require mutual TLS. Use socket-based communication only.",
    },

    # ── 7. S3 public + sensitive files ───────────────────────────────────
    {
        "id":          "s3_data_breach",
        "name":        "Public S3 Bucket + Sensitive Files → Data Breach",
        "severity":    "Critical",
        "cvss_key":    "Chain_Data_Exfil",
        "description": "An S3 bucket is publicly readable AND contains sensitive files (credentials, backups, PII).",
        "impact":      "Mass data breach — all bucket contents accessible to anyone.",
        "components":  ["S3 Public Read Access", "Sensitive Files in Bucket"],
        "check": lambda r: any(
            f.get("public_read") and f.get("sensitive_files")
            for f in r.get("cloud", {}).get("s3", {}).get("findings", [])
        ),
        "remediation": "Enable S3 Block Public Access. Rotate exposed credentials. Audit bucket contents.",
    },

    # ── 8. GraphQL introspection + unauthenticated ────────────────────────
    {
        "id":          "graphql_data_map",
        "name":        "GraphQL Introspection + No Auth → Full Data Mapping",
        "severity":    "High",
        "cvss_key":    "Chain_Data_Exfil",
        "description": "GraphQL schema is fully exposed via introspection AND sensitive data is accessible without authentication.",
        "impact":      "Attacker maps entire API, identifies sensitive fields, extracts all data.",
        "components":  ["GraphQL Introspection Enabled", "Unauthenticated Data Access"],
        "check": lambda r: (
            _has_finding(r, "business", "introspection", "GraphQL Introspection") and
            _has_finding(r, "business", "unauthenticated", "unauth")
        ),
        "remediation": "Disable introspection in production. Require authentication on all GraphQL resolvers.",
    },

    # ── 9. Weak TLS + sensitive data ─────────────────────────────────────
    {
        "id":          "weak_tls_data_intercept",
        "name":        "Weak TLS + Sensitive Endpoints → Data Interception",
        "severity":    "High",
        "cvss_key":    "Chain_Session_Hijack",
        "description": "TLS grade is C or below AND the site handles authentication/sensitive data. Traffic can be downgraded and intercepted.",
        "impact":      "Session cookies and credentials interceptable via network downgrade attack.",
        "components":  ["Weak TLS (Grade C or below)", "Authentication endpoints accessible"],
        "check": lambda r: (
            r.get("tls", {}).get("grade") in ("C", "D", "F") and
            _has_finding(r, "directories", "login", "api", "auth")
        ),
        "remediation": "Upgrade TLS to 1.2/1.3. Enable HSTS with preload. Disable weak cipher suites.",
    },

    # ── 10. Server banner + known CVE ────────────────────────────────────
    {
        "id":          "banner_cve_exploit",
        "name":        "Server Version Disclosure → Known CVE Exploitation",
        "severity":    "High",
        "cvss_key":    "Chain_RCE",
        "description": "Server software version is exposed in response headers AND a CVE exists for that version. Version disclosure provides a roadmap for targeted attacks.",
        "impact":      "Attacker immediately knows which exploits to run against the server.",
        "components":  ["Server Banner Disclosure", "CVE for Disclosed Version"],
        "check": lambda r: (
            r.get("banner", {}).get("severity") in ("High", "Critical") and
            len(r.get("ports", {}).get("open_ports", [])) > 0
        ),
        "remediation": "Remove Server and X-Powered-By headers. Update all software to latest versions.",
    },
]


def detect_chains(all_results: dict) -> list:
    """
    Run all chain rules against the combined scan results.
    Returns list of confirmed vulnerability chains with CVSS scores.
    """
    chains = []
    for rule in CHAIN_RULES:
        try:
            if rule["check"](all_results):
                from .cvss_scorer import score_finding
                cvss = score_finding(rule["cvss_key"], rule["severity"])
                chains.append({
                    "id":          rule["id"],
                    "name":        rule["name"],
                    "severity":    rule["severity"],
                    "description": rule["description"],
                    "impact":      rule["impact"],
                    "components":  rule["components"],
                    "remediation": rule["remediation"],
                    "cvss":        cvss,
                    "type":        "chain",
                })
        except Exception:
            continue

    return chains

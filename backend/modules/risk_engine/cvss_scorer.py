# backend/modules/risk_engine/cvss_scorer.py
# CVSS v3.1 scoring for all finding types across all modules
# Uses manual formula implementation (no external lib dependency issues)

import math

# ── CVSS v3.1 metric weights ──────────────────────────────────────────────────
AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC  = {"L": 0.77, "H": 0.44}
PR  = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI  = {"N": 0.85, "R": 0.62}
S   = {"U": "Unchanged", "C": "Changed"}
CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

def _iss(c, i, a):
    return 1 - (1 - CIA[c]) * (1 - CIA[i]) * (1 - CIA[a])

def _impact(scope, c, i, a):
    iss = _iss(c, i, a)
    if scope == "U":
        return 6.42 * iss
    else:
        return 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

def _exploitability(av, ac, pr, ui, scope):
    pr_val = PR_CHANGED[pr] if scope == "C" else PR[pr]
    return 8.22 * AV[av] * AC[ac] * pr_val * UI[ui]

def calculate_cvss(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H") -> dict:
    """
    Calculate CVSS v3.1 Base Score.
    Returns score (0-10), severity label, and vector string.
    """
    imp   = _impact(s, c, i, a)
    exp   = _exploitability(av, ac, pr, ui, s)

    if imp <= 0:
        base = 0.0
    else:
        if s == "U":
            base = min(imp + exp, 10)
        else:
            base = min(1.08 * (imp + exp), 10)
        # Round up to 1 decimal
        base = math.ceil(base * 10) / 10

    if base == 0:
        severity = "None"
    elif base < 4.0:
        severity = "Low"
    elif base < 7.0:
        severity = "Medium"
    elif base < 9.0:
        severity = "High"
    else:
        severity = "Critical"

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    return {
        "score":    round(base, 1),
        "severity": severity,
        "vector":   vector,
        "metrics":  {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a},
    }


# ── Pre-defined CVSS profiles for each finding type ──────────────────────────
# Maps finding type/category → CVSS parameters

FINDING_CVSS_PROFILES = {
    # Header findings
    "Content-Security-Policy_Missing":       dict(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N"),
    "Content-Security-Policy_Weak":          dict(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N"),
    "Strict-Transport-Security_Missing":     dict(av="N", ac="H", pr="N", ui="R", s="U", c="H", i="L", a="N"),
    "X-Frame-Options_Missing":               dict(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N"),
    "X-Content-Type-Options_Missing":        dict(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N"),

    # TLS findings
    "TLS_Grade_F":                           dict(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "TLS_Grade_C":                           dict(av="N", ac="H", pr="N", ui="N", s="U", c="L", i="L", a="N"),
    "TLS_Cert_Expired":                      dict(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="L", a="H"),

    # Port findings
    "Port_Database_Exposed":                 dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "Port_Redis_Exposed":                    dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "Port_Docker_Exposed":                   dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "Port_SSH_Exposed":                      dict(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "Port_FTP_Exposed":                      dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),

    # Directory findings
    "Git_Exposed":                           dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "Env_File_Exposed":                      dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "Admin_Panel_Exposed":                   dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "Backup_Exposed":                        dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "phpMyAdmin_Exposed":                    dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "API_Endpoint_Exposed":                  dict(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="L", a="N"),

    # CORS findings
    "CORS_Origin_Reflection_With_Creds":     dict(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    "CORS_Origin_Reflection":                dict(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="L", a="N"),
    "CORS_Wildcard":                         dict(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="N", a="N"),
    "CORS_Null_Origin":                      dict(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="L", a="N"),

    # JWT findings
    "JWT_Alg_None":                          dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "JWT_Weak_Secret":                       dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "JWT_Expired_Accepted":                  dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "JWT_Invalid_Accepted":                  dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),

    # GraphQL findings
    "GraphQL_Introspection":                 dict(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "GraphQL_Unauth_Data":                   dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "GraphQL_Batching":                      dict(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="L", a="H"),

    # Secret findings
    "Secret_AWS_Key":                        dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "Secret_Private_Key":                    dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "Secret_Database_URL":                   dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "Secret_Generic_Password":               dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "Secret_API_Key":                        dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"),

    # Cloud findings
    "S3_Public_Read":                        dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "S3_Exists":                             dict(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "Subdomain_Takeover":                    dict(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    "Docker_API_Exposed":                    dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "Kubernetes_Exposed":                    dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "Elasticsearch_Exposed":                 dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "Jenkins_RCE":                           dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "Swagger_Exposed":                       dict(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),

    # Vulnerability chains (always high/critical)
    "Chain_Session_Hijack":                  dict(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    "Chain_RCE":                             dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "Chain_XSS_Takeover":                    dict(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    "Chain_Data_Exfil":                      dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),

    # Default fallback
    "_default_critical":                     dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "_default_high":                         dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "_default_medium":                       dict(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N"),
    "_default_low":                          dict(av="N", ac="H", pr="L", ui="R", s="U", c="L", i="N", a="N"),
}


def score_finding(finding_type: str, severity_hint: str = "Medium") -> dict:
    """
    Look up the CVSS profile for a finding type and calculate the score.
    Falls back to severity-based default if no exact match.
    """
    profile = FINDING_CVSS_PROFILES.get(finding_type)
    if not profile:
        fallback_key = f"_default_{severity_hint.lower()}"
        profile = FINDING_CVSS_PROFILES.get(fallback_key, FINDING_CVSS_PROFILES["_default_medium"])

    return calculate_cvss(**profile)


def score_findings_batch(findings: list) -> list:
    """
    Score a list of findings. Each finding must have 'type' and optionally 'severity'.
    Returns findings with 'cvss' key added.
    """
    scored = []
    for f in findings:
        ftype    = f.get("type", f.get("test", f.get("header", "unknown")))
        severity = f.get("severity", "Medium")
        cvss     = score_finding(ftype, severity)
        scored.append({**f, "cvss": cvss})
    return sorted(scored, key=lambda x: x["cvss"]["score"], reverse=True)
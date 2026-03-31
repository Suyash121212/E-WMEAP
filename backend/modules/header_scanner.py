# modules/header_scanner.py
# Module 1 — Security Header Analysis (Advanced)
# Covers: header presence, CSP deep parsing, Mozilla Observatory, scoring

import re
import requests

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; E-WMEAP-Scanner/1.0)"
})

# ── Reference links shown in the UI ──────────────────────────────────────────
HEADER_REFS = {
    "Content-Security-Policy":        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    "Strict-Transport-Security":      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    "X-Frame-Options":                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    "X-Content-Type-Options":         "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    "Referrer-Policy":                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    "Permissions-Policy":             "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    "Cross-Origin-Opener-Policy":     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy":   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
}

# ── CSP deep analysis ─────────────────────────────────────────────────────────

DANGEROUS_CSP_VALUES = [
    "unsafe-inline",
    "unsafe-eval",
    "unsafe-hashes",
    "data:",       # allows data: URIs as script source
    "*",           # wildcard source
]

REQUIRED_CSP_DIRECTIVES = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "frame-ancestors",
    "base-uri",
    "form-action",
]

def analyze_csp(csp_value: str) -> dict:
    """
    Deeply parse a CSP header value.
    Returns directives found, dangerous values, missing important directives,
    and a PoC XSS payload if unsafe-inline is present.
    """
    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]

    dangerous = []
    for directive, values in directives.items():
        for v in values:
            if any(d in v for d in DANGEROUS_CSP_VALUES):
                dangerous.append(f"{directive}: {v}")

    missing = [d for d in REQUIRED_CSP_DIRECTIVES if d not in directives]
    deprecated = []
    if "report-uri" in directives:
        deprecated.append("report-uri is deprecated — replace with report-to directive")

    poc_payload = None
    script_vals = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in script_vals or "unsafe-inline" in " ".join(script_vals):
        poc_payload = "<script>alert('E-WMEAP XSS PoC — unsafe-inline confirmed')</script>"

    return {
        "directives_found": list(directives.keys()),
        "dangerous_directives": dangerous,
        "missing_directives": missing,
        "deprecated_directives": deprecated,
        "poc_payload": poc_payload,
    }

# ── Individual header checks ──────────────────────────────────────────────────

def check_csp(headers: dict) -> dict:
    base = {
        "header": "Content-Security-Policy",
        "reference": HEADER_REFS["Content-Security-Policy"],
    }
    if "Content-Security-Policy" not in headers:
        return {**base,
            "value": "Not Present",
            "status": "Missing",
            "severity": "High",
            "impact": "No CSP policy — XSS attacks can inject and execute arbitrary scripts.",
            "recommendation": "Add a strict Content-Security-Policy header. Start with default-src 'self' and extend as needed.",
            "csp_analysis": None,
        }

    value = headers["Content-Security-Policy"]
    csp = analyze_csp(value)

    if csp["dangerous_directives"]:
        return {**base,
            "value": value,
            "status": "Weak Configuration",
            "severity": "High",
            "impact": "CSP is present but allows unsafe directives. XSS may still be possible.",
            "recommendation": "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes instead.",
            "csp_analysis": csp,
        }

    return {**base,
        "value": value,
        "status": "Secure",
        "severity": "None",
        "impact": "Strong CSP configuration detected.",
        "recommendation": None,
        "csp_analysis": csp,
    }


def check_hsts(headers: dict) -> dict:
    base = {
        "header": "Strict-Transport-Security",
        "reference": HEADER_REFS["Strict-Transport-Security"],
    }
    if "Strict-Transport-Security" not in headers:
        return {**base,
            "value": "Not Present",
            "status": "Missing",
            "severity": "High",
            "impact": "Without HSTS, users can be downgraded from HTTPS to HTTP (SSL stripping).",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        }

    value = headers["Strict-Transport-Security"]

    if "max-age=0" in value:
        return {**base,
            "value": value,
            "status": "Weak Configuration",
            "severity": "High",
            "impact": "HSTS max-age is 0 — effectively disabled.",
            "recommendation": "Set max-age to at least 31536000 (1 year).",
        }

    # Check max-age value
    match = re.search(r"max-age=(\d+)", value)
    if match:
        max_age = int(match.group(1))
        if max_age < 2592000:  # < 30 days
            return {**base,
                "value": value,
                "status": "Weak Configuration",
                "severity": "Medium",
                "impact": f"HSTS max-age is only {max_age}s (< 30 days). Too short for preload eligibility.",
                "recommendation": "Increase max-age to at least 31536000 (1 year) and add 'preload'.",
            }

    return {**base,
        "value": value,
        "status": "Secure",
        "severity": "None",
        "impact": "HSTS properly enforced.",
        "recommendation": None,
    }


def check_xframe(headers: dict) -> dict:
    base = {
        "header": "X-Frame-Options",
        "reference": HEADER_REFS["X-Frame-Options"],
    }
    if "X-Frame-Options" not in headers:
        return {**base,
            "value": "Not Present",
            "status": "Missing",
            "severity": "Medium",
            "impact": "Site can be embedded in iframes — clickjacking attacks possible.",
            "recommendation": "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors instead).",
        }

    value = headers["X-Frame-Options"]
    if "ALLOW-FROM" in value.upper():
        return {**base,
            "value": value,
            "status": "Weak Configuration",
            "severity": "Medium",
            "impact": "ALLOW-FROM is deprecated and not supported in modern browsers.",
            "recommendation": "Replace with CSP frame-ancestors directive for cross-browser support.",
        }

    return {**base,
        "value": value,
        "status": "Secure",
        "severity": "None",
        "impact": "Clickjacking protection enabled.",
        "recommendation": None,
    }


def check_xcto(headers: dict) -> dict:
    base = {
        "header": "X-Content-Type-Options",
        "reference": HEADER_REFS["X-Content-Type-Options"],
    }
    if "X-Content-Type-Options" not in headers:
        return {**base,
            "value": "Not Present",
            "status": "Missing",
            "severity": "Medium",
            "impact": "Browser may MIME-sniff responses, enabling content-type confusion attacks.",
            "recommendation": "Add: X-Content-Type-Options: nosniff",
        }

    value = headers["X-Content-Type-Options"]
    if value.lower() != "nosniff":
        return {**base,
            "value": value,
            "status": "Weak Configuration",
            "severity": "Medium",
            "impact": "Value must be exactly 'nosniff'.",
            "recommendation": "Set: X-Content-Type-Options: nosniff",
        }

    return {**base,
        "value": value,
        "status": "Secure",
        "severity": "None",
        "impact": "MIME sniffing protection enabled.",
        "recommendation": None,
    }


def check_referrer_policy(headers: dict) -> dict:
    base = {
        "header": "Referrer-Policy",
        "reference": HEADER_REFS["Referrer-Policy"],
    }
    if "Referrer-Policy" not in headers:
        return {**base,
            "value": "Not Present",
            "status": "Missing",
            "severity": "Low",
            "impact": "Full URL may be sent as Referer header, leaking sensitive path/query data.",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        }

    value = headers["Referrer-Policy"]
    weak_values = ["unsafe-url", "no-referrer-when-downgrade"]
    if value.lower() in weak_values:
        return {**base,
            "value": value,
            "status": "Weak Configuration",
            "severity": "Low",
            "impact": "Referrer policy sends full URLs cross-origin, potentially leaking data.",
            "recommendation": "Use: strict-origin-when-cross-origin or no-referrer",
        }

    return {**base,
        "value": value,
        "status": "Secure",
        "severity": "None",
        "impact": "Referrer policy configured.",
        "recommendation": None,
    }


def check_permissions_policy(headers: dict) -> dict:
    base = {
        "header": "Permissions-Policy",
        "reference": HEADER_REFS["Permissions-Policy"],
    }
    if "Permissions-Policy" not in headers:
        return {**base,
            "value": "Not Present",
            "status": "Missing",
            "severity": "Low",
            "impact": "Browser features (camera, microphone, geolocation) are not explicitly restricted.",
            "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        }
    return {**base,
        "value": headers["Permissions-Policy"],
        "status": "Secure",
        "severity": "None",
        "impact": "Permissions policy configured.",
        "recommendation": None,
    }


def check_coop(headers: dict) -> dict:
    base = {
        "header": "Cross-Origin-Opener-Policy",
        "reference": HEADER_REFS["Cross-Origin-Opener-Policy"],
    }
    if "Cross-Origin-Opener-Policy" not in headers:
        return {**base,
            "value": "Not Present",
            "status": "Missing",
            "severity": "Medium",
            "impact": "Cross-origin windows can reference this window — Spectre-style attacks possible.",
            "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
        }
    return {**base,
        "value": headers["Cross-Origin-Opener-Policy"],
        "status": "Secure",
        "severity": "None",
        "impact": "Cross-origin opener policy enabled.",
        "recommendation": None,
    }


def check_corp(headers: dict) -> dict:
    base = {
        "header": "Cross-Origin-Resource-Policy",
        "reference": HEADER_REFS["Cross-Origin-Resource-Policy"],
    }
    if "Cross-Origin-Resource-Policy" not in headers:
        return {**base,
            "value": "Not Present",
            "status": "Missing",
            "severity": "Medium",
            "impact": "Resources can be embedded by cross-origin sites.",
            "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
        }
    return {**base,
        "value": headers["Cross-Origin-Resource-Policy"],
        "status": "Secure",
        "severity": "None",
        "impact": "Cross-origin resource policy configured.",
        "recommendation": None,
    }

# ── Mozilla Observatory integration ──────────────────────────────────────────

def fetch_observatory(domain: str) -> dict | None:
    """
    Calls Mozilla HTTP Observatory API (free, no key needed).
    Returns grade and score, or None on failure.
    """
    try:
        trigger = requests.post(
            "https://http-observatory.security.mozilla.org/api/v1/analyze",
            params={"host": domain},
            data={"hidden": "true"},
            timeout=15,
        )
        data = trigger.json()

        # Observatory may return cached result immediately
        if data.get("state") == "FINISHED":
            return {"grade": data.get("grade"), "score": data.get("score")}

        # Poll once more after short wait (keep it simple for project)
        import time
        time.sleep(4)
        poll = requests.get(
            "https://http-observatory.security.mozilla.org/api/v1/analyze",
            params={"host": domain},
            timeout=10,
        )
        data = poll.json()
        if data.get("state") == "FINISHED":
            return {"grade": data.get("grade"), "score": data.get("score")}

        return None
    except Exception:
        return None

# ── Score calculation ─────────────────────────────────────────────────────────

SEVERITY_DEDUCTIONS = {"High": 18, "Medium": 9, "Low": 3, "None": 0}

def calculate_score(findings: list) -> int:
    deductions = sum(SEVERITY_DEDUCTIONS.get(f["severity"], 0) for f in findings)
    return max(0, 100 - deductions)

# ── Main entry point ──────────────────────────────────────────────────────────

def analyze_headers(url: str) -> dict:
    try:
        response = SESSION.get(url, allow_redirects=True, timeout=10)
        headers = response.headers

        findings = [
            check_csp(headers),
            check_hsts(headers),
            check_xframe(headers),
            check_xcto(headers),
            check_referrer_policy(headers),
            check_permissions_policy(headers),
            check_coop(headers),
            check_corp(headers),
        ]

        score = calculate_score(findings)

        # Extract domain for Observatory (strip scheme + path)
        from urllib.parse import urlparse
        domain = urlparse(url).netloc or url

        observatory = fetch_observatory(domain)

        return {
            "target": url,
            "total_headers_checked": len(findings),
            "score": score,
            "findings": findings,
            "observatory": observatory,
        }

    except requests.exceptions.ConnectionError:
        return {"error": f"Could not connect to {url}"}
    except requests.exceptions.Timeout:
        return {"error": f"Request to {url} timed out"}
    except Exception as e:
        return {"error": str(e)}
    


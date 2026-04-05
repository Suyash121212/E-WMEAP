import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT_SECONDS = 10
OBSERVATORY_TRIGGER_TIMEOUT_SECONDS = 15
OBSERVATORY_POLL_TIMEOUT_SECONDS = 10
OBSERVATORY_POLL_DELAY_SECONDS = 4
SCANNER_USER_AGENT = "Mozilla/5.0 (compatible; E-WMEAP-Scanner/1.0)"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": SCANNER_USER_AGENT})

HEADER_REFS = {
    "Content-Security-Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    "Strict-Transport-Security": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    "X-Frame-Options": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    "X-Content-Type-Options": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    "Referrer-Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    "Permissions-Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    "Cross-Origin-Opener-Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
}

DANGEROUS_CSP_VALUES = [
    "unsafe-inline",
    "unsafe-eval",
    "unsafe-hashes",
    "data:",
    "*",
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

SEVERITY_DEDUCTIONS = {"High": 18, "Medium": 9, "Low": 3, "None": 0}


def _build_finding(
    header: str,
    *,
    value: str,
    status: str,
    severity: str,
    impact: str,
    recommendation: Optional[str],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    finding = {
        "header": header,
        "reference": HEADER_REFS[header],
        "value": value,
        "status": status,
        "severity": severity,
        "impact": impact,
        "recommendation": recommendation,
    }
    if extra:
        finding.update(extra)
    return finding


def _request_json(url: str, *, timeout: int, **kwargs: Any) -> Optional[Any]:
    try:
        response = SESSION.get(url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return None
    except ValueError:
        return None


def analyze_csp(csp_value: str) -> Dict[str, Any]:
    directives: Dict[str, List[str]] = {}
    for part in csp_value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]

    dangerous = []
    for directive, values in directives.items():
        for value in values:
            if any(flag in value for flag in DANGEROUS_CSP_VALUES):
                dangerous.append(f"{directive}: {value}")

    deprecated = []
    if "report-uri" in directives:
        deprecated.append("report-uri is deprecated - replace with report-to directive")

    script_values = directives.get("script-src", directives.get("default-src", []))
    has_unsafe_inline = "'unsafe-inline'" in script_values or "unsafe-inline" in " ".join(script_values)

    return {
        "directives_found": list(directives.keys()),
        "dangerous_directives": dangerous,
        "missing_directives": [directive for directive in REQUIRED_CSP_DIRECTIVES if directive not in directives],
        "deprecated_directives": deprecated,
        "poc_payload": "<script>alert('E-WMEAP XSS PoC - unsafe-inline confirmed')</script>" if has_unsafe_inline else None,
    }


def check_csp(headers: Dict[str, str]) -> Dict[str, Any]:
    header = "Content-Security-Policy"
    value = headers.get(header)
    if not value:
        return _build_finding(
            header,
            value="Not Present",
            status="Missing",
            severity="High",
            impact="No CSP policy - XSS attacks can inject and execute arbitrary scripts.",
            recommendation="Add a strict Content-Security-Policy header. Start with default-src 'self' and extend as needed.",
            extra={"csp_analysis": None},
        )

    csp_analysis = analyze_csp(value)
    if csp_analysis["dangerous_directives"]:
        return _build_finding(
            header,
            value=value,
            status="Weak Configuration",
            severity="High",
            impact="CSP is present but allows unsafe directives. XSS may still be possible.",
            recommendation="Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes instead.",
            extra={"csp_analysis": csp_analysis},
        )

    return _build_finding(
        header,
        value=value,
        status="Secure",
        severity="None",
        impact="Strong CSP configuration detected.",
        recommendation=None,
        extra={"csp_analysis": csp_analysis},
    )


def check_hsts(headers: Dict[str, str]) -> Dict[str, Any]:
    header = "Strict-Transport-Security"
    value = headers.get(header)
    if not value:
        return _build_finding(
            header,
            value="Not Present",
            status="Missing",
            severity="High",
            impact="Without HSTS, users can be downgraded from HTTPS to HTTP (SSL stripping).",
            recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        )

    if "max-age=0" in value:
        return _build_finding(
            header,
            value=value,
            status="Weak Configuration",
            severity="High",
            impact="HSTS max-age is 0 - effectively disabled.",
            recommendation="Set max-age to at least 31536000 (1 year).",
        )

    match = re.search(r"max-age=(\d+)", value)
    if match and int(match.group(1)) < 2592000:
        max_age = int(match.group(1))
        return _build_finding(
            header,
            value=value,
            status="Weak Configuration",
            severity="Medium",
            impact=f"HSTS max-age is only {max_age}s (< 30 days). Too short for preload eligibility.",
            recommendation="Increase max-age to at least 31536000 (1 year) and add 'preload'.",
        )

    return _build_finding(
        header,
        value=value,
        status="Secure",
        severity="None",
        impact="HSTS properly enforced.",
        recommendation=None,
    )


def check_xframe(headers: Dict[str, str]) -> Dict[str, Any]:
    header = "X-Frame-Options"
    value = headers.get(header)
    if not value:
        return _build_finding(
            header,
            value="Not Present",
            status="Missing",
            severity="Medium",
            impact="Site can be embedded in iframes - clickjacking attacks possible.",
            recommendation="Add: X-Frame-Options: DENY (or use CSP frame-ancestors instead).",
        )

    if "ALLOW-FROM" in value.upper():
        return _build_finding(
            header,
            value=value,
            status="Weak Configuration",
            severity="Medium",
            impact="ALLOW-FROM is deprecated and not supported in modern browsers.",
            recommendation="Replace with CSP frame-ancestors directive for cross-browser support.",
        )

    return _build_finding(
        header,
        value=value,
        status="Secure",
        severity="None",
        impact="Clickjacking protection enabled.",
        recommendation=None,
    )


def check_xcto(headers: Dict[str, str]) -> Dict[str, Any]:
    header = "X-Content-Type-Options"
    value = headers.get(header)
    if not value:
        return _build_finding(
            header,
            value="Not Present",
            status="Missing",
            severity="Medium",
            impact="Browser may MIME-sniff responses, enabling content-type confusion attacks.",
            recommendation="Add: X-Content-Type-Options: nosniff",
        )

    if value.lower() != "nosniff":
        return _build_finding(
            header,
            value=value,
            status="Weak Configuration",
            severity="Medium",
            impact="Value must be exactly 'nosniff'.",
            recommendation="Set: X-Content-Type-Options: nosniff",
        )

    return _build_finding(
        header,
        value=value,
        status="Secure",
        severity="None",
        impact="MIME sniffing protection enabled.",
        recommendation=None,
    )


def check_referrer_policy(headers: Dict[str, str]) -> Dict[str, Any]:
    header = "Referrer-Policy"
    value = headers.get(header)
    if not value:
        return _build_finding(
            header,
            value="Not Present",
            status="Missing",
            severity="Low",
            impact="Full URL may be sent as Referer header, leaking sensitive path/query data.",
            recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
        )

    if value.lower() in {"unsafe-url", "no-referrer-when-downgrade"}:
        return _build_finding(
            header,
            value=value,
            status="Weak Configuration",
            severity="Low",
            impact="Referrer policy sends full URLs cross-origin, potentially leaking data.",
            recommendation="Use: strict-origin-when-cross-origin or no-referrer",
        )

    return _build_finding(
        header,
        value=value,
        status="Secure",
        severity="None",
        impact="Referrer policy configured.",
        recommendation=None,
    )


def check_permissions_policy(headers: Dict[str, str]) -> Dict[str, Any]:
    header = "Permissions-Policy"
    value = headers.get(header)
    if not value:
        return _build_finding(
            header,
            value="Not Present",
            status="Missing",
            severity="Low",
            impact="Browser features (camera, microphone, geolocation) are not explicitly restricted.",
            recommendation="Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        )

    return _build_finding(
        header,
        value=value,
        status="Secure",
        severity="None",
        impact="Permissions policy configured.",
        recommendation=None,
    )


def check_coop(headers: Dict[str, str]) -> Dict[str, Any]:
    header = "Cross-Origin-Opener-Policy"
    value = headers.get(header)
    if not value:
        return _build_finding(
            header,
            value="Not Present",
            status="Missing",
            severity="Medium",
            impact="Cross-origin windows can reference this window - Spectre-style attacks possible.",
            recommendation="Add: Cross-Origin-Opener-Policy: same-origin",
        )

    return _build_finding(
        header,
        value=value,
        status="Secure",
        severity="None",
        impact="Cross-origin opener policy enabled.",
        recommendation=None,
    )


def check_corp(headers: Dict[str, str]) -> Dict[str, Any]:
    header = "Cross-Origin-Resource-Policy"
    value = headers.get(header)
    if not value:
        return _build_finding(
            header,
            value="Not Present",
            status="Missing",
            severity="Medium",
            impact="Resources can be embedded by cross-origin sites.",
            recommendation="Add: Cross-Origin-Resource-Policy: same-origin",
        )

    return _build_finding(
        header,
        value=value,
        status="Secure",
        severity="None",
        impact="Cross-origin resource policy configured.",
        recommendation=None,
    )


def fetch_observatory(domain: str) -> Optional[Dict[str, Any]]:
    try:
        trigger = SESSION.post(
            "https://http-observatory.security.mozilla.org/api/v1/analyze",
            params={"host": domain},
            data={"hidden": "true"},
            timeout=OBSERVATORY_TRIGGER_TIMEOUT_SECONDS,
        )
        trigger.raise_for_status()
        data = trigger.json()
        if data.get("state") == "FINISHED":
            return {"grade": data.get("grade"), "score": data.get("score")}

        import time

        time.sleep(OBSERVATORY_POLL_DELAY_SECONDS)
        poll_data = _request_json(
            "https://http-observatory.security.mozilla.org/api/v1/analyze",
            timeout=OBSERVATORY_POLL_TIMEOUT_SECONDS,
            params={"host": domain},
        )
        if isinstance(poll_data, dict) and poll_data.get("state") == "FINISHED":
            return {"grade": poll_data.get("grade"), "score": poll_data.get("score")}
        return None
    except (requests.RequestException, ValueError):
        return None


def calculate_score(findings: List[Dict[str, Any]]) -> int:
    deductions = sum(SEVERITY_DEDUCTIONS.get(finding["severity"], 0) for finding in findings)
    return max(0, 100 - deductions)


def analyze_headers(url: str) -> Dict[str, Any]:
    try:
        response = SESSION.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        headers = dict(response.headers)
    except requests.exceptions.ConnectionError:
        return {"error": f"Could not connect to {url}"}
    except requests.exceptions.Timeout:
        return {"error": f"Request to {url} timed out"}
    except requests.RequestException as exc:
        return {"error": str(exc)}

    checks: List[Callable[[Dict[str, str]], Dict[str, Any]]] = [
        check_csp,
        check_hsts,
        check_xframe,
        check_xcto,
        check_referrer_policy,
        check_permissions_policy,
        check_coop,
        check_corp,
    ]
    findings = [check(headers) for check in checks]
    domain = urlparse(url).netloc or url

    return {
        "target": url,
        "total_headers_checked": len(findings),
        "score": calculate_score(findings),
        "findings": findings,
        "observatory": fetch_observatory(domain),
    }

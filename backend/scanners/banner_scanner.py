import requests
import re


def detect_server_banner(url: str) -> dict:
    """
    Sends an HTTP request to the target URL and extracts server banner information
    including Server header, X-Powered-By header, detected technology, and version.
    """
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "E-WMEAP/1.0 Security Scanner"}
        )
        headers = response.headers
    except requests.exceptions.RequestException as e:
        return {
            "server": "Unreachable",
            "powered_by": "N/A",
            "technology": "N/A",
            "version": "N/A",
            "severity": "None",
            "impact": "Could not connect to target.",
            "recommendation": "Verify the URL is correct and the server is reachable."
        }

    server_header = headers.get("Server", "")
    powered_by_header = headers.get("X-Powered-By", "")

    technology, version = _parse_technology(server_header, powered_by_header)
    severity = _determine_severity(server_header, powered_by_header, version)
    impact = _determine_impact(severity)
    recommendation = _determine_recommendation(severity)

    return {
        "server": server_header if server_header else "Not Disclosed",
        "powered_by": powered_by_header if powered_by_header else "Not Disclosed",
        "technology": technology,
        "version": version,
        "severity": severity,
        "impact": impact,
        "recommendation": recommendation
    }


def _parse_technology(server: str, powered_by: str) -> tuple[str, str]:
    combined = f"{server} {powered_by}".lower()
    version = "Not Detected"
    technology = "Unknown"

    tech_patterns = [
        ("nginx",     r"nginx(?:[/\s]([\d.]+))?",         "nginx"),
        ("apache",    r"apache(?:[/\s]([\d.]+))?",        "Apache"),
        ("iis",       r"iis(?:[/\s]([\d.]+))?",           "Microsoft IIS"),
        ("litespeed", r"litespeed(?:[/\s]([\d.]+))?",     "LiteSpeed"),
        ("caddy",     r"caddy(?:[/\s]([\d.]+))?",         "Caddy"),
        ("node",      r"node(?:\.js)?(?:[/\s]([\d.]+))?", "Node.js"),
        ("express",   r"express(?:[/\s]([\d.]+))?",       "Express.js"),
        ("php",       r"php(?:[/\s]([\d.]+))?",           "PHP"),
        ("django",    r"django(?:[/\s]([\d.]+))?",        "Django"),
        ("werkzeug",  r"werkzeug(?:[/\s]([\d.]+))?",      "Flask/Werkzeug"),
        ("rails",     r"rails(?:[/\s]([\d.]+))?",         "Ruby on Rails"),
        ("tomcat",    r"tomcat(?:[/\s]([\d.]+))?",        "Apache Tomcat"),
        ("jetty",     r"jetty(?:[/\s]([\d.]+))?",         "Jetty"),
        ("gunicorn",  r"gunicorn(?:[/\s]([\d.]+))?",      "Gunicorn"),
        ("cloudflare",r"cloudflare",                      "Cloudflare"),  # no version
    ]

    for key, pattern, label in tech_patterns:
        if key in combined:
            technology = label
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                groups = match.groups()
                if groups and groups[0]:
                    version = groups[0]
            break

    # Generic fallback
    if technology == "Unknown":
        match = re.search(r"([\w\-]+)[/\s]([\d]+\.[\d.]+)", f"{server} {powered_by}", re.IGNORECASE)
        if match:
            technology = match.group(1).capitalize()
            version = match.group(2)
        elif server:
            technology = server.split("/")[0].strip().capitalize()
        elif powered_by:
            technology = powered_by.split("/")[0].strip().capitalize()

    return technology, version


def _determine_severity(server: str, powered_by: str, version: str) -> str:
    if not server and not powered_by:
        return "None"
    if version != "Not Detected":
        return "Medium"
    if server or powered_by:
        return "Low"
    return "None"


def _determine_impact(severity: str) -> str:
    impacts = {
        "Medium": (
            "Specific version information is exposed, allowing attackers to identify "
            "known CVEs and target unpatched vulnerabilities."
        ),
        "Low": (
            "The web server technology is disclosed. This reduces attacker effort "
            "during reconnaissance, enabling more targeted attacks."
        ),
        "None": (
            "No server information is exposed. The server banner is properly suppressed."
        ),
    }
    return impacts.get(severity, "Unknown impact.")


def _determine_recommendation(severity: str) -> str:
    recommendations = {
        "Medium": (
            "Remove or obfuscate the Server and X-Powered-By headers entirely. "
            "Configure your web server to suppress version information (e.g., "
            "'ServerTokens Prod' for Apache, 'server_tokens off' for nginx)."
        ),
        "Low": (
            "Consider suppressing the Server and X-Powered-By headers to reduce "
            "information leakage. Technology disclosure aids attacker reconnaissance."
        ),
        "None": (
            "No action required. Server banner is properly hidden."
        ),
    }
    return recommendations.get(severity, "Review server configuration.")
# modules/tls_scanner.py
# Module 1 (Part 2) — TLS / SSL Analysis
# Uses ssl stdlib (no tools needed) + optional SSL Labs API (free)

import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse


def _get_cert_info(hostname: str, port: int = 443) -> dict:
    """
    Connect via SSL and extract certificate details directly.
    No external API needed — uses Python's ssl module.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                # Parse expiry
                expiry_str = cert.get("notAfter", "")
                expiry_dt  = None
                cert_expired = False
                days_left = None
                if expiry_str:
                    expiry_dt = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.utcnow()
                    cert_expired = expiry_dt < now
                    days_left = (expiry_dt - now).days

                # Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer_dict.get("organizationName", "Unknown")

                # Subject (CN)
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                common_name = subject_dict.get("commonName", hostname)

                # SAN list
                san_list = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]

                return {
                    "protocol": protocol,
                    "issuer": issuer,
                    "common_name": common_name,
                    "cert_expiry": expiry_dt.strftime("%Y-%m-%d") if expiry_dt else None,
                    "cert_expired": cert_expired,
                    "days_left": days_left,
                    "san_count": len(san_list),
                }
    except ssl.SSLError as e:
        return {"error": f"SSL error: {e}"}
    except socket.timeout:
        return {"error": "Connection timed out"}
    except Exception as e:
        return {"error": str(e)}


def _check_hsts_preload(hostname: str) -> bool:
    """Query the HSTS preload list via hstspreload.org API (free)."""
    try:
        r = requests.get(
            f"https://hstspreload.org/api/v2/status?domain={hostname}",
            timeout=6
        )
        data = r.json()
        return data.get("status") == "preloaded"
    except Exception:
        return False


def _derive_grade(cert_info: dict, hsts_preload: bool) -> str:
    """
    Simple grade derivation from what we know without SSL Labs.
    SSL Labs is async and slow — this gives an instant grade.
    For the project, you can add SSL Labs polling as an enhancement later.
    """
    if cert_info.get("error"):
        return "F"
    if cert_info.get("cert_expired"):
        return "F"

    protocol = cert_info.get("protocol", "")
    if "TLSv1" == protocol or "SSLv3" in protocol:
        return "C"
    if "TLSv1.1" == protocol:
        return "B"

    days_left = cert_info.get("days_left", 999)
    if days_left is not None and days_left < 30:
        return "B"

    if hsts_preload:
        return "A+"

    return "A"


def _get_issues(cert_info: dict, hsts_preload: bool) -> list:
    issues = []
    if cert_info.get("cert_expired"):
        issues.append("Certificate has expired — browsers will show a security warning")
    if cert_info.get("days_left") is not None and 0 < cert_info["days_left"] < 30:
        issues.append(f"Certificate expires in {cert_info['days_left']} days — renew soon")
    protocol = cert_info.get("protocol", "")
    if protocol in ("TLSv1", "TLSv1.1"):
        issues.append(f"Outdated TLS version ({protocol}) — upgrade to TLS 1.2 or 1.3")
    if not hsts_preload:
        issues.append("Domain is not on the HSTS preload list")
    return issues


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze_tls(url: str) -> dict:
    parsed   = urlparse(url)
    hostname = parsed.netloc or parsed.path
    hostname = hostname.split(":")[0]   # strip port if present

    # Only works on HTTPS
    if parsed.scheme == "http":
        return {
            "error": "TLS analysis requires HTTPS. Target is using plain HTTP.",
            "protocol": "HTTP",
            "grade": "N/A",
        }

    cert_info    = _get_cert_info(hostname)
    hsts_preload = _check_hsts_preload(hostname)

    if cert_info.get("error"):
        return {
            "error": cert_info["error"],
            "grade": "F",
            "protocol": None,
            "hsts_preload": False,
        }

    grade  = _derive_grade(cert_info, hsts_preload)
    issues = _get_issues(cert_info, hsts_preload)

    return {
        "hostname":     hostname,
        "grade":        grade,
        "protocol":     cert_info.get("protocol"),
        "issuer":       cert_info.get("issuer"),
        "cert_expiry":  cert_info.get("cert_expiry"),
        "cert_expired": cert_info.get("cert_expired"),
        "days_left":    cert_info.get("days_left"),
        "common_name":  cert_info.get("common_name"),
        "san_count":    cert_info.get("san_count"),
        "hsts_preload": hsts_preload,
        "issues":       issues,
    }


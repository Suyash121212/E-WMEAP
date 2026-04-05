import datetime
import socket
import ssl
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

SOCKET_TIMEOUT_SECONDS = 8
HSTS_PRELOAD_TIMEOUT_SECONDS = 6
PRELOAD_API_URL = "https://hstspreload.org/api/v2/status"

SESSION = requests.Session()


def _extract_hostname(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    return hostname.split(":", maxsplit=1)[0]


def _build_error_result(error: str, protocol: Optional[str] = None) -> Dict[str, Any]:
    return {
        "error": error,
        "grade": "F" if protocol != "HTTP" else "N/A",
        "protocol": protocol,
        "hsts_preload": False,
    }


def _get_cert_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Connect via SSL and extract certificate details directly."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=SOCKET_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_socket:
                cert = secure_socket.getpeercert()
                protocol = secure_socket.version()
                expiry_dt = _parse_certificate_expiry(cert.get("notAfter", ""))
                now = datetime.datetime.utcnow()
                days_left = (expiry_dt - now).days if expiry_dt else None

                return {
                    "protocol": protocol,
                    "issuer": _extract_name_field(cert.get("issuer", []), "organizationName", "Unknown"),
                    "common_name": _extract_name_field(cert.get("subject", []), "commonName", hostname),
                    "cert_expiry": expiry_dt.strftime("%Y-%m-%d") if expiry_dt else None,
                    "cert_expired": bool(expiry_dt and expiry_dt < now),
                    "days_left": days_left,
                    "san_count": len([value for item_type, value in cert.get("subjectAltName", []) if item_type == "DNS"]),
                }
    except ssl.SSLError as exc:
        return {"error": f"SSL error: {exc}"}
    except socket.timeout:
        return {"error": "Connection timed out"}
    except OSError as exc:
        return {"error": str(exc)}


def _parse_certificate_expiry(expiry_str: str) -> Optional[datetime.datetime]:
    if not expiry_str:
        return None
    return datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")


def _extract_name_field(entries: Any, field_name: str, fallback: str) -> str:
    try:
        values = dict(item[0] for item in entries)
    except (TypeError, ValueError, IndexError):
        return fallback
    return values.get(field_name, fallback)


def _check_hsts_preload(hostname: str) -> bool:
    """Query the HSTS preload list via hstspreload.org."""
    try:
        response = SESSION.get(
            PRELOAD_API_URL,
            params={"domain": hostname},
            timeout=HSTS_PRELOAD_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response.json().get("status") == "preloaded"
    except (requests.RequestException, ValueError):
        return False


def _derive_grade(cert_info: Dict[str, Any], hsts_preload: bool) -> str:
    if cert_info.get("error") or cert_info.get("cert_expired"):
        return "F"

    protocol = cert_info.get("protocol", "")
    if protocol in {"TLSv1", "TLSv1.0"} or "SSLv3" in protocol:
        return "C"
    if protocol == "TLSv1.1":
        return "B"

    days_left = cert_info.get("days_left", 999)
    if days_left is not None and days_left < 30:
        return "B"
    if hsts_preload:
        return "A+"
    return "A"


def _get_issues(cert_info: Dict[str, Any], hsts_preload: bool) -> list[str]:
    issues: list[str] = []
    if cert_info.get("cert_expired"):
        issues.append("Certificate has expired - browsers will show a security warning")
    if cert_info.get("days_left") is not None and 0 < cert_info["days_left"] < 30:
        issues.append(f"Certificate expires in {cert_info['days_left']} days - renew soon")

    protocol = cert_info.get("protocol", "")
    if protocol in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
        issues.append(f"Outdated TLS version ({protocol}) - upgrade to TLS 1.2 or 1.3")
    if not hsts_preload:
        issues.append("Domain is not on the HSTS preload list")
    return issues


def analyze_tls(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    hostname = _extract_hostname(url)

    if parsed.scheme == "http":
        return _build_error_result(
            "TLS analysis requires HTTPS. Target is using plain HTTP.",
            protocol="HTTP",
        )

    cert_info = _get_cert_info(hostname)
    if cert_info.get("error"):
        return _build_error_result(str(cert_info["error"]))

    hsts_preload = _check_hsts_preload(hostname)
    return {
        "hostname": hostname,
        "grade": _derive_grade(cert_info, hsts_preload),
        "protocol": cert_info.get("protocol"),
        "issuer": cert_info.get("issuer"),
        "cert_expiry": cert_info.get("cert_expiry"),
        "cert_expired": cert_info.get("cert_expired"),
        "days_left": cert_info.get("days_left"),
        "common_name": cert_info.get("common_name"),
        "san_count": cert_info.get("san_count"),
        "hsts_preload": hsts_preload,
        "issues": _get_issues(cert_info, hsts_preload),
    }

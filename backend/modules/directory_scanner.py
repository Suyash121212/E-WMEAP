import json
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

SCANNER_USER_AGENT = "Mozilla/5.0 (compatible; E-WMEAP-Scanner/1.0)"
HTTP_TIMEOUT_SECONDS = 6
GRAPHQL_TIMEOUT_SECONDS = 8
SUBPROCESS_TIMEOUT_SECONDS = 60
MAX_CONTENT_PREVIEW_BYTES = 50_000
MAX_CONTENT_PREVIEW_CHARS = 500
MAX_WORKERS = 20

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": SCANNER_USER_AGENT})
SESSION.max_redirects = 3

# Each entry: (path, category, severity, description)
PATHS = [
    ("/.git/config", "source_control", "Critical", "Git config file - repository metadata exposed"),
    ("/.git/HEAD", "source_control", "Critical", "Git HEAD pointer - confirms .git directory exists"),
    ("/.git/COMMIT_EDITMSG", "source_control", "Critical", "Git commit message - confirms source code access"),
    ("/.svn/entries", "source_control", "High", "SVN repository entries exposed"),
    ("/.hg/store/00manifest", "source_control", "High", "Mercurial repository exposed"),
    ("/.env", "secrets", "Critical", "Environment file - may contain DB credentials, API keys"),
    ("/.env.local", "secrets", "Critical", "Local environment overrides with secrets"),
    ("/.env.production", "secrets", "Critical", "Production environment file"),
    ("/.env.backup", "secrets", "Critical", "Environment file backup"),
    ("/.env.example", "secrets", "Medium", "Example env file - reveals expected secret names"),
    ("/config.php", "secrets", "High", "PHP config file - may contain DB credentials"),
    ("/config.json", "secrets", "High", "JSON config - may contain API keys"),
    ("/configuration.php", "secrets", "High", "CMS configuration file"),
    ("/wp-config.php", "secrets", "Critical", "WordPress config - DB password exposed"),
    ("/settings.py", "secrets", "High", "Django settings - SECRET_KEY and DB config"),
    ("/.aws/credentials", "secrets", "Critical", "AWS credentials file"),
    ("/credentials.json", "secrets", "Critical", "Credentials file exposed"),
    ("/admin", "admin", "High", "Admin panel - authentication bypass risk"),
    ("/admin/", "admin", "High", "Admin panel directory"),
    ("/administrator", "admin", "High", "Administrator panel"),
    ("/administrator/", "admin", "High", "Administrator panel directory"),
    ("/wp-admin/", "admin", "High", "WordPress admin panel"),
    ("/wp-login.php", "admin", "High", "WordPress login page"),
    ("/admin/login", "admin", "High", "Admin login endpoint"),
    ("/dashboard", "admin", "Medium", "Dashboard - may be unprotected"),
    ("/control", "admin", "Medium", "Control panel"),
    ("/manager", "admin", "Medium", "Manager interface"),
    ("/phpmyadmin", "admin", "Critical", "phpMyAdmin - direct database access"),
    ("/phpmyadmin/", "admin", "Critical", "phpMyAdmin directory"),
    ("/pma", "admin", "Critical", "phpMyAdmin shortcut"),
    ("/backup", "backup", "Critical", "Backup directory"),
    ("/backup/", "backup", "Critical", "Backup directory"),
    ("/backup.zip", "backup", "Critical", "Compressed backup archive"),
    ("/backup.tar.gz", "backup", "Critical", "Compressed backup archive"),
    ("/backup.sql", "backup", "Critical", "SQL database dump"),
    ("/db.sql", "backup", "Critical", "Database dump file"),
    ("/database.sql", "backup", "Critical", "Database dump file"),
    ("/dump.sql", "backup", "Critical", "Database dump"),
    ("/site.zip", "backup", "High", "Full site archive"),
    ("/old/", "backup", "Medium", "Old version directory"),
    ("/bak/", "backup", "Medium", "Backup directory shorthand"),
    ("/api", "api", "Medium", "API root - endpoint enumeration possible"),
    ("/api/", "api", "Medium", "API root directory"),
    ("/api/v1", "api", "Medium", "API version 1"),
    ("/api/v1/", "api", "Medium", "API version 1 directory"),
    ("/api/v2", "api", "Medium", "API version 2"),
    ("/api/v2/", "api", "Medium", "API version 2 directory"),
    ("/api/users", "api", "High", "User data API endpoint"),
    ("/api/admin", "api", "High", "Admin API endpoint"),
    ("/graphql", "api", "High", "GraphQL endpoint - introspection may be enabled"),
    ("/graphiql", "api", "High", "GraphiQL IDE - interactive query interface exposed"),
    ("/swagger", "api", "Medium", "Swagger UI - full API documentation exposed"),
    ("/swagger-ui.html", "api", "Medium", "Swagger UI page"),
    ("/api-docs", "api", "Medium", "API documentation"),
    ("/openapi.json", "api", "Medium", "OpenAPI specification"),
    ("/server-status", "server_info", "High", "Apache server-status - live request data"),
    ("/server-info", "server_info", "High", "Apache server-info - module and config data"),
    ("/phpinfo.php", "server_info", "High", "PHP info page - full server configuration"),
    ("/info.php", "server_info", "High", "PHP info page"),
    ("/test.php", "server_info", "Medium", "Test PHP file - may expose server info"),
    ("/debug", "server_info", "High", "Debug endpoint - may expose stack traces"),
    ("/debug/", "server_info", "High", "Debug directory"),
    ("/trace", "server_info", "Medium", "Trace endpoint"),
    ("/actuator", "server_info", "High", "Spring Boot actuator - health/env data"),
    ("/actuator/env", "server_info", "Critical", "Spring Boot env actuator - exposes env vars"),
    ("/actuator/health", "server_info", "Low", "Spring Boot health endpoint"),
    ("/.DS_Store", "metadata", "Medium", "macOS metadata - reveals directory structure"),
    ("/robots.txt", "metadata", "Low", "Robots.txt - may reveal hidden paths"),
    ("/sitemap.xml", "metadata", "Low", "Sitemap - reveals all site URLs"),
    ("/.htaccess", "metadata", "Medium", ".htaccess - server config rules"),
    ("/crossdomain.xml", "metadata", "Low", "Flash cross-domain policy"),
    ("/humans.txt", "metadata", "Low", "Humans.txt - may reveal team info"),
    ("/security.txt", "metadata", "Low", "Security.txt - security contact info"),
    ("/.well-known/security.txt", "metadata", "Low", "Security.txt standard location"),
    ("/logs/", "logs", "High", "Log directory exposed"),
    ("/log/", "logs", "High", "Log directory"),
    ("/error.log", "logs", "High", "Error log file"),
    ("/access.log", "logs", "High", "Access log - user activity data"),
    ("/debug.log", "logs", "High", "Debug log - may contain credentials"),
    ("/laravel.log", "logs", "High", "Laravel application log"),
    ("/storage/logs/laravel.log", "logs", "High", "Laravel log in storage"),
]

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".env", ".json", ".yaml", ".yml",
    ".php", ".rb", ".go", ".java", ".config", ".cfg", ".ini", ".txt",
}
MANUAL_SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    ("Stripe Secret", r"sk_live_[0-9a-zA-Z]{24}"),
    ("Private Key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("Generic Password", r'(?i)password\s*[=:]\s*["\'][^"\']{6,}["\']'),
    ("Generic API Key", r'(?i)api[_\-]?key\s*[=:]\s*["\'][^"\']{8,}["\']'),
    ("Database URL", r'(?i)(mysql|postgres|mongodb):\/\/[^\s"\']+'),
    ("JWT Token", r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"),
    ("Secret Key", r'(?i)secret[_\-]?key\s*[=:]\s*["\'][^"\']{8,}["\']'),
]
SENSITIVE_ENV_KEYWORDS = [
    "password", "secret", "key", "token", "api", "db", "database",
    "aws", "stripe", "twilio", "sendgrid", "jwt", "auth", "private",
]


def _safe_request(method: str, url: str, **kwargs: Any) -> Optional[requests.Response]:
    try:
        return SESSION.request(method, url, **kwargs)
    except requests.RequestException:
        return None


def _probe(base_url: str, path: str) -> Optional[Dict[str, Any]]:
    url = f"{base_url.rstrip('/')}{path}"
    response = _safe_request("GET", url, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=False)
    if response is None:
        return None

    status = response.status_code
    if status == 404 or status >= 500:
        return None

    content_preview = None
    if status == 200 and len(response.content) < MAX_CONTENT_PREVIEW_BYTES:
        content_preview = response.text[:MAX_CONTENT_PREVIEW_CHARS]

    return {
        "status": status,
        "content_preview": content_preview,
        "content_length": len(response.content),
        "redirect_location": response.headers.get("Location"),
    }


def _run_subprocess(command: List[str], *, timeout: int = SUBPROCESS_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def _poc_git(base_url: str) -> Dict[str, Any]:
    result = {
        "tool": "git-dumper + truffleHog",
        "reconstructed": False,
        "files_found": [],
        "secrets": [],
        "error": None,
    }

    git_dumper = shutil.which("git-dumper")
    if not git_dumper:
        result["error"] = (
            "git-dumper not installed. Install with: pip install git-dumper "
            "then re-run the scan to reconstruct source code."
        )
        return result

    temp_dir = tempfile.mkdtemp(prefix="ewmeap_git_")
    try:
        process = _run_subprocess([git_dumper, f"{base_url.rstrip('/')}/.git", temp_dir])
        if process.returncode != 0 and not os.listdir(temp_dir):
            result["error"] = f"git-dumper failed: {process.stderr[:300]}"
            return result

        result["reconstructed"] = True
        result["files_found"] = _list_reconstructed_files(temp_dir)

        trufflehog = shutil.which("trufflehog") or shutil.which("truffleHog")
        if trufflehog:
            trufflehog_process = _run_subprocess([trufflehog, "filesystem", temp_dir, "--json", "--no-update"])
            result["secrets"] = _parse_trufflehog(trufflehog_process.stdout)
        else:
            result["secrets"] = _manual_secret_scan(temp_dir)
    except subprocess.TimeoutExpired:
        result["error"] = f"git-dumper timed out ({SUBPROCESS_TIMEOUT_SECONDS}s)"
    except OSError as exc:
        result["error"] = str(exc)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return result


def _list_reconstructed_files(directory: str) -> List[str]:
    files_found: List[str] = []
    for root, _, files in os.walk(directory):
        for filename in files:
            relative_path = os.path.relpath(os.path.join(root, filename), directory)
            files_found.append(relative_path)
    return files_found[:30]


def _parse_trufflehog(output: str) -> List[Dict[str, str]]:
    secrets: List[Dict[str, str]] = []
    for line in output.strip().splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        raw_value = item.get("Raw", "") or item.get("RawV2", "")
        if not raw_value:
            continue

        source_data = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        secrets.append(
            {
                "type": item.get("DetectorName", "Unknown"),
                "file": source_data.get("file", "unknown"),
                "snippet": _mask_secret(raw_value),
            }
        )
    return secrets[:10]


def _manual_secret_scan(directory: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    for root, _, files in os.walk(directory):
        for filename in files:
            if os.path.splitext(filename)[1].lower() not in TEXT_EXTENSIONS:
                continue

            file_path = os.path.join(root, filename)
            try:
                with open(file_path, "r", errors="ignore") as file_handle:
                    content = file_handle.read()
            except OSError:
                continue

            for name, pattern in MANUAL_SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    findings.append(
                        {
                            "type": name,
                            "file": os.path.relpath(file_path, directory),
                            "snippet": _mask_secret(match.group(0)),
                        }
                    )
                    if len(findings) >= 10:
                        return findings

    return findings


def _mask_secret(value: str) -> str:
    masked = value.strip()
    if len(masked) <= 12:
        return f"{masked[:3]}***"
    return f"{masked[:6]}***{masked[-4:]}"


def _poc_env(content: str) -> Dict[str, Any]:
    keys_found: List[str] = []
    sensitive_keys: List[Dict[str, str]] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", maxsplit=1)
        key = key.strip()
        value = value.strip()
        keys_found.append(key)

        if any(keyword in key.lower() for keyword in SENSITIVE_ENV_KEYWORDS):
            sensitive_keys.append(
                {
                    "key": key,
                    "masked_value": _mask_secret(value) if value else "(empty)",
                }
            )

    return {
        "keys_found": keys_found,
        "sensitive_keys": sensitive_keys,
        "total_keys": len(keys_found),
    }


def _poc_graphql(base_url: str, path: str) -> Dict[str, Any]:
    response = _safe_request(
        "POST",
        f"{base_url.rstrip('/')}{path}",
        json={"query": "{ __schema { types { name fields { name } } } }"},
        timeout=GRAPHQL_TIMEOUT_SECONDS,
    )
    if response is None or response.status_code != 200:
        return {"introspection_enabled": False}

    try:
        data = response.json()
    except ValueError:
        return {"introspection_enabled": False}

    if "data" not in data or "__schema" not in str(data):
        return {"introspection_enabled": False}

    types = data.get("data", {}).get("__schema", {}).get("types", [])
    type_names = [item["name"] for item in types if not item["name"].startswith("__")]
    return {
        "introspection_enabled": True,
        "types_found": type_names[:20],
        "sensitive_types": [
            type_name for type_name in type_names
            if any(keyword in type_name.lower() for keyword in ["user", "password", "token", "admin", "secret", "key", "auth"])
        ],
    }


def _parse_robots(content: str) -> List[str]:
    hidden_paths: List[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line.lower().startswith("disallow:"):
            continue
        path = line.split(":", maxsplit=1)[1].strip()
        if path and path != "/":
            hidden_paths.append(path)
    return hidden_paths[:20]


def _overall_severity(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "None"
    return min(findings, key=lambda item: SEV_ORDER.get(item["severity"], 99))["severity"]


def _build_finding(base_url: str, entry: Tuple[str, str, str, str]) -> Optional[Dict[str, Any]]:
    path, category, severity, description = entry
    probe_result = _probe(base_url, path)
    if probe_result is None:
        return None

    finding = {
        "path": path,
        "full_url": f"{base_url}{path}",
        "category": category,
        "severity": severity,
        "description": description,
        "status_code": probe_result["status"],
        "status_label": _status_label(probe_result["status"]),
        "content_length": probe_result["content_length"],
        "redirect_to": probe_result["redirect_location"],
        "poc": None,
    }

    content_preview = probe_result.get("content_preview")
    if path in {"/.git/config", "/.git/HEAD"} and probe_result["status"] == 200:
        finding["poc"] = {"type": "git_reconstruction", "data": _poc_git(base_url)}
    elif "/.env" in path and probe_result["status"] == 200 and content_preview:
        finding["poc"] = {"type": "env_parse", "data": _poc_env(content_preview)}
    elif path in {"/graphql", "/graphiql"} and probe_result["status"] in {200, 400}:
        finding["poc"] = {"type": "graphql_introspection", "data": _poc_graphql(base_url, path)}
    elif path == "/robots.txt" and probe_result["status"] == 200 and content_preview:
        hidden_paths = _parse_robots(content_preview)
        if hidden_paths:
            finding["poc"] = {"type": "robots_hidden_paths", "data": {"hidden_paths": hidden_paths}}

    return finding


def scan_directories(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    findings: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(_build_finding, base_url, entry) for entry in PATHS]
        for future in as_completed(futures):
            try:
                finding = future.result()
            except Exception:
                continue
            if finding:
                findings.append(finding)

    findings.sort(key=lambda item: (SEV_ORDER.get(item["severity"], 99), item["path"]))

    severity_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}
    for finding in findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
        category_counts[finding["category"]] = category_counts.get(finding["category"], 0) + 1

    overall = _overall_severity(findings)
    return {
        "target": base_url,
        "total_paths_checked": len(PATHS),
        "total_found": len(findings),
        "overall_severity": overall,
        "risk_summary": _build_risk_summary(findings),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "findings": findings,
    }


def _status_label(code: int) -> str:
    return {
        200: "Accessible",
        301: "Redirect (301)",
        302: "Redirect (302)",
        403: "Forbidden (exists)",
        401: "Requires Auth",
        405: "Method Not Allowed",
    }.get(code, str(code))


def _build_risk_summary(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "No sensitive paths or directories found."

    critical = [finding for finding in findings if finding["severity"] == "Critical"]
    high = [finding for finding in findings if finding["severity"] == "High"]
    summary_parts: List[str] = []

    if critical:
        summary_parts.append(f"{len(critical)} critical path(s) exposed: {', '.join(f['path'] for f in critical[:3])}")
    if high:
        summary_parts.append(f"{len(high)} high-severity path(s) found")
    if any("/.git" in finding["path"] for finding in findings):
        summary_parts.append("source code reconstruction possible via .git")
    if any("/.env" in finding["path"] for finding in findings):
        summary_parts.append("credentials may be exposed via .env")

    return ". ".join(summary_parts) + "." if summary_parts else f"{len(findings)} paths found."

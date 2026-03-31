# backend/modules/directory_scanner.py
# Module 4 — Directory & Endpoint Discovery + PoC Generation
#
# Flow:
#   1. Threaded HTTP probing against categorised path list
#   2. Risk classification per finding
#   3. PoC generation:
#        - .git  → git-dumper → truffleHog → masked secrets
#        - .env  → fetch & parse key names
#        - admin → screenshot URL + auth bypass check
#   4. Returns structured JSON consumed by DirectoryScanner.jsx

import os
import re
import json
import shutil
import tempfile
import subprocess
import threading
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Session ───────────────────────────────────────────────────────────────────
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; E-WMEAP-Scanner/1.0)",
})
SESSION.max_redirects = 3

# ── Path definitions ──────────────────────────────────────────────────────────
# Each entry: (path, category, severity, description)
PATHS = [
    # Source control
    ("/.git/config",            "source_control",  "Critical", "Git config file — repository metadata exposed"),
    ("/.git/HEAD",              "source_control",  "Critical", "Git HEAD pointer — confirms .git directory exists"),
    ("/.git/COMMIT_EDITMSG",    "source_control",  "Critical", "Git commit message — confirms source code access"),
    ("/.svn/entries",           "source_control",  "High",     "SVN repository entries exposed"),
    ("/.hg/store/00manifest",   "source_control",  "High",     "Mercurial repository exposed"),

    # Environment & secrets
    ("/.env",                   "secrets",         "Critical", "Environment file — may contain DB credentials, API keys"),
    ("/.env.local",             "secrets",         "Critical", "Local environment overrides with secrets"),
    ("/.env.production",        "secrets",         "Critical", "Production environment file"),
    ("/.env.backup",            "secrets",         "Critical", "Environment file backup"),
    ("/.env.example",           "secrets",         "Medium",   "Example env file — reveals expected secret names"),
    ("/config.php",             "secrets",         "High",     "PHP config file — may contain DB credentials"),
    ("/config.json",            "secrets",         "High",     "JSON config — may contain API keys"),
    ("/configuration.php",      "secrets",         "High",     "CMS configuration file"),
    ("/wp-config.php",          "secrets",         "Critical", "WordPress config — DB password exposed"),
    ("/settings.py",            "secrets",         "High",     "Django settings — SECRET_KEY and DB config"),
    ("/.aws/credentials",       "secrets",         "Critical", "AWS credentials file"),
    ("/credentials.json",       "secrets",         "Critical", "Credentials file exposed"),

    # Admin panels
    ("/admin",                  "admin",           "High",     "Admin panel — authentication bypass risk"),
    ("/admin/",                 "admin",           "High",     "Admin panel directory"),
    ("/administrator",          "admin",           "High",     "Administrator panel"),
    ("/administrator/",         "admin",           "High",     "Administrator panel directory"),
    ("/wp-admin/",              "admin",           "High",     "WordPress admin panel"),
    ("/wp-login.php",           "admin",           "High",     "WordPress login page"),
    ("/admin/login",            "admin",           "High",     "Admin login endpoint"),
    ("/dashboard",              "admin",           "Medium",   "Dashboard — may be unprotected"),
    ("/control",                "admin",           "Medium",   "Control panel"),
    ("/manager",                "admin",           "Medium",   "Manager interface"),
    ("/phpmyadmin",             "admin",           "Critical", "phpMyAdmin — direct database access"),
    ("/phpmyadmin/",            "admin",           "Critical", "phpMyAdmin directory"),
    ("/pma",                    "admin",           "Critical", "phpMyAdmin shortcut"),

    # Backup & database dumps
    ("/backup",                 "backup",          "Critical", "Backup directory"),
    ("/backup/",                "backup",          "Critical", "Backup directory"),
    ("/backup.zip",             "backup",          "Critical", "Compressed backup archive"),
    ("/backup.tar.gz",          "backup",          "Critical", "Compressed backup archive"),
    ("/backup.sql",             "backup",          "Critical", "SQL database dump"),
    ("/db.sql",                 "backup",          "Critical", "Database dump file"),
    ("/database.sql",           "backup",          "Critical", "Database dump file"),
    ("/dump.sql",               "backup",          "Critical", "Database dump"),
    ("/site.zip",               "backup",          "High",     "Full site archive"),
    ("/old/",                   "backup",          "Medium",   "Old version directory"),
    ("/bak/",                   "backup",          "Medium",   "Backup directory shorthand"),

    # API endpoints
    ("/api",                    "api",             "Medium",   "API root — endpoint enumeration possible"),
    ("/api/",                   "api",             "Medium",   "API root directory"),
    ("/api/v1",                 "api",             "Medium",   "API version 1"),
    ("/api/v1/",                "api",             "Medium",   "API version 1 directory"),
    ("/api/v2",                 "api",             "Medium",   "API version 2"),
    ("/api/v2/",                "api",             "Medium",   "API version 2 directory"),
    ("/api/users",              "api",             "High",     "User data API endpoint"),
    ("/api/admin",              "api",             "High",     "Admin API endpoint"),
    ("/graphql",                "api",             "High",     "GraphQL endpoint — introspection may be enabled"),
    ("/graphiql",               "api",             "High",     "GraphiQL IDE — interactive query interface exposed"),
    ("/swagger",                "api",             "Medium",   "Swagger UI — full API documentation exposed"),
    ("/swagger-ui.html",        "api",             "Medium",   "Swagger UI page"),
    ("/api-docs",               "api",             "Medium",   "API documentation"),
    ("/openapi.json",           "api",             "Medium",   "OpenAPI specification"),

    # Server info
    ("/server-status",          "server_info",     "High",     "Apache server-status — live request data"),
    ("/server-info",            "server_info",     "High",     "Apache server-info — module and config data"),
    ("/phpinfo.php",            "server_info",     "High",     "PHP info page — full server configuration"),
    ("/info.php",               "server_info",     "High",     "PHP info page"),
    ("/test.php",               "server_info",     "Medium",   "Test PHP file — may expose server info"),
    ("/debug",                  "server_info",     "High",     "Debug endpoint — may expose stack traces"),
    ("/debug/",                 "server_info",     "High",     "Debug directory"),
    ("/trace",                  "server_info",     "Medium",   "Trace endpoint"),
    ("/actuator",               "server_info",     "High",     "Spring Boot actuator — health/env data"),
    ("/actuator/env",           "server_info",     "Critical", "Spring Boot env actuator — exposes env vars"),
    ("/actuator/health",        "server_info",     "Low",      "Spring Boot health endpoint"),

    # Metadata
    ("/.DS_Store",              "metadata",        "Medium",   "macOS metadata — reveals directory structure"),
    ("/robots.txt",             "metadata",        "Low",      "Robots.txt — may reveal hidden paths"),
    ("/sitemap.xml",            "metadata",        "Low",      "Sitemap — reveals all site URLs"),
    ("/.htaccess",              "metadata",        "Medium",   ".htaccess — server config rules"),
    ("/crossdomain.xml",        "metadata",        "Low",      "Flash cross-domain policy"),
    ("/humans.txt",             "metadata",        "Low",      "Humans.txt — may reveal team info"),
    ("/security.txt",           "metadata",        "Low",      "Security.txt — security contact info"),
    ("/.well-known/security.txt","metadata",       "Low",      "Security.txt standard location"),

    # Log files
    ("/logs/",                  "logs",            "High",     "Log directory exposed"),
    ("/log/",                   "logs",            "High",     "Log directory"),
    ("/error.log",              "logs",            "High",     "Error log file"),
    ("/access.log",             "logs",            "High",     "Access log — user activity data"),
    ("/debug.log",              "logs",            "High",     "Debug log — may contain credentials"),
    ("/laravel.log",            "logs",            "High",     "Laravel application log"),
    ("/storage/logs/laravel.log","logs",           "High",     "Laravel log in storage"),
]

# ── Severity ordering ─────────────────────────────────────────────────────────
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# ── HTTP probe ────────────────────────────────────────────────────────────────

def _probe(base_url: str, path: str) -> dict | None:
    """
    Send a GET request to base_url+path.
    Returns finding dict if interesting (200, 301, 302, 403), else None.
    403 is still interesting — it means the path exists but is protected.
    """
    url = base_url.rstrip("/") + path
    try:
        r = SESSION.get(url, timeout=6, allow_redirects=False)
        status = r.status_code

        # 404 / 5xx = not interesting
        if status == 404 or status >= 500:
            return None

        # Collect content snippet for .env and similar
        content_preview = None
        if status == 200 and len(r.content) < 50_000:
            content_preview = r.text[:500]

        return {
            "status": status,
            "content_preview": content_preview,
            "content_length": len(r.content),
            "redirect_location": r.headers.get("Location", None),
        }
    except Exception:
        return None

# ── PoC: .git reconstruction ──────────────────────────────────────────────────

def _poc_git(base_url: str) -> dict:
    """
    If git-dumper is installed: clone the repo, then run truffleHog.
    If not installed: explain what would happen.
    """
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
            "git-dumper not installed. "
            "Install with: pip install git-dumper  "
            "then re-run the scan to reconstruct source code."
        )
        return result

    tmp_dir = tempfile.mkdtemp(prefix="ewmeap_git_")
    try:
        # Run git-dumper
        proc = subprocess.run(
            [git_dumper, f"{base_url.rstrip('/')}/.git", tmp_dir],
            capture_output=True, text=True, timeout=60,
        )

        if proc.returncode != 0 and not os.listdir(tmp_dir):
            result["error"] = f"git-dumper failed: {proc.stderr[:300]}"
            return result

        result["reconstructed"] = True

        # List files found
        for root, _, files in os.walk(tmp_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), tmp_dir)
                result["files_found"].append(rel)
        result["files_found"] = result["files_found"][:30]  # cap at 30

        # Run truffleHog
        truffle = shutil.which("trufflehog") or shutil.which("truffleHog")
        if truffle:
            th_proc = subprocess.run(
                [truffle, "filesystem", tmp_dir, "--json", "--no-update"],
                capture_output=True, text=True, timeout=60,
            )
            secrets = _parse_trufflehog(th_proc.stdout)
            result["secrets"] = secrets
        else:
            # Fallback: manual regex scan
            result["secrets"] = _manual_secret_scan(tmp_dir)

    except subprocess.TimeoutExpired:
        result["error"] = "git-dumper timed out (60s)"
    except Exception as e:
        result["error"] = str(e)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


def _parse_trufflehog(output: str) -> list:
    """Parse truffleHog JSON output into clean secret list."""
    secrets = []
    for line in output.strip().splitlines():
        try:
            obj = json.loads(line)
            raw = obj.get("Raw", "") or obj.get("RawV2", "")
            det = obj.get("DetectorName", "Unknown")
            src = obj.get("SourceMetadata", {})
            file_path = (
                src.get("Data", {}).get("Filesystem", {}).get("file", "unknown")
            )
            if raw:
                secrets.append({
                    "type":    det,
                    "file":    file_path,
                    "snippet": _mask_secret(raw),
                })
        except Exception:
            continue
    return secrets[:10]  # cap


def _manual_secret_scan(directory: str) -> list:
    """
    Regex-based secret scan used when truffleHog is not installed.
    Covers most common secret patterns.
    """
    PATTERNS = [
        ("AWS Access Key",    r"AKIA[0-9A-Z]{16}"),
        ("Google API Key",    r"AIza[0-9A-Za-z\-_]{35}"),
        ("GitHub Token",      r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        ("Stripe Secret",     r"sk_live_[0-9a-zA-Z]{24}"),
        ("Private Key",       r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        ("Generic Password",  r'(?i)password\s*[=:]\s*["\'][^"\']{6,}["\']'),
        ("Generic API Key",   r'(?i)api[_\-]?key\s*[=:]\s*["\'][^"\']{8,}["\']'),
        ("Database URL",      r'(?i)(mysql|postgres|mongodb):\/\/[^\s"\']+'),
        ("JWT Token",         r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"),
        ("Secret Key",        r'(?i)secret[_\-]?key\s*[=:]\s*["\'][^"\']{8,}["\']'),
    ]

    findings = []
    text_extensions = {
        ".py", ".js", ".ts", ".env", ".json", ".yaml", ".yml",
        ".php", ".rb", ".go", ".java", ".config", ".cfg", ".ini", ".txt",
    }

    for root, _, files in os.walk(directory):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in text_extensions:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                for name, pattern in PATTERNS:
                    for match in re.finditer(pattern, content):
                        findings.append({
                            "type":    name,
                            "file":    os.path.relpath(fpath, directory),
                            "snippet": _mask_secret(match.group(0)),
                        })
                        if len(findings) >= 10:
                            return findings
            except Exception:
                continue
    return findings


def _mask_secret(value: str) -> str:
    """Show first 6 and last 4 chars, mask the middle."""
    v = value.strip()
    if len(v) <= 12:
        return v[:3] + "***"
    return v[:6] + "***" + v[-4:]

# ── PoC: .env parsing ─────────────────────────────────────────────────────────

def _poc_env(content: str) -> dict:
    """Parse a fetched .env file — extract key names (not values)."""
    keys_found = []
    sensitive_keys = []
    SENSITIVE = ["password", "secret", "key", "token", "api", "db", "database",
                 "aws", "stripe", "twilio", "sendgrid", "jwt", "auth", "private"]

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key = line.split("=")[0].strip()
            value = line.split("=", 1)[1].strip()
            keys_found.append(key)
            if any(s in key.lower() for s in SENSITIVE):
                # Mask the value
                masked = _mask_secret(value) if value else "(empty)"
                sensitive_keys.append({"key": key, "masked_value": masked})

    return {
        "keys_found": keys_found,
        "sensitive_keys": sensitive_keys,
        "total_keys": len(keys_found),
    }

# ── PoC: GraphQL introspection ────────────────────────────────────────────────

def _poc_graphql(base_url: str, path: str) -> dict:
    """Send GraphQL introspection query — if it works, schema is exposed."""
    url = base_url.rstrip("/") + path
    introspection = {
        "query": "{ __schema { types { name fields { name } } } }"
    }
    try:
        r = SESSION.post(url, json=introspection, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if "data" in data and "__schema" in str(data):
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                type_names = [t["name"] for t in types if not t["name"].startswith("__")]
                return {
                    "introspection_enabled": True,
                    "types_found": type_names[:20],
                    "sensitive_types": [
                        t for t in type_names
                        if any(s in t.lower() for s in
                               ["user", "password", "token", "admin", "secret", "key", "auth"])
                    ],
                }
    except Exception:
        pass
    return {"introspection_enabled": False}

# ── PoC: robots.txt parser ────────────────────────────────────────────────────

def _parse_robots(content: str) -> list:
    """Extract Disallow paths from robots.txt — these are paths worth checking."""
    hidden = []
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                hidden.append(path)
    return hidden[:20]

# ── Risk summary ──────────────────────────────────────────────────────────────

def _overall_severity(findings: list) -> str:
    if not findings:
        return "None"
    top = min(findings, key=lambda f: SEV_ORDER.get(f["severity"], 99))
    return top["severity"]

# ── Main entry point ──────────────────────────────────────────────────────────

def scan_directories(url: str) -> dict:
    """
    Full directory & endpoint discovery scan.
    Returns structured result consumed by the React frontend.
    """
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    findings    = []
    poc_results = {}
    robots_hidden = []

    # ── Threaded probing ──────────────────────────────────────────────────────
    def probe_one(entry):
        path, category, severity, description = entry
        result = _probe(base_url, path)
        if result is None:
            return None

        finding = {
            "path":        path,
            "full_url":    base_url + path,
            "category":    category,
            "severity":    severity,
            "description": description,
            "status_code": result["status"],
            "status_label": _status_label(result["status"]),
            "content_length": result["content_length"],
            "redirect_to": result["redirect_location"],
            "poc":         None,
        }

        # ── PoC triggers ─────────────────────────────────────────────────────

        # .git → full reconstruction
        if path in ("/.git/config", "/.git/HEAD") and result["status"] == 200:
            finding["poc"] = {
                "type": "git_reconstruction",
                "data": _poc_git(base_url),
            }

        # .env → parse key names
        elif "/.env" in path and result["status"] == 200 and result["content_preview"]:
            finding["poc"] = {
                "type": "env_parse",
                "data": _poc_env(result["content_preview"]),
            }

        # GraphQL → introspection
        elif path in ("/graphql", "/graphiql") and result["status"] in (200, 400):
            finding["poc"] = {
                "type": "graphql_introspection",
                "data": _poc_graphql(base_url, path),
            }

        # robots.txt → extract hidden paths
        elif path == "/robots.txt" and result["status"] == 200 and result["content_preview"]:
            hidden = _parse_robots(result["content_preview"])
            if hidden:
                finding["poc"] = {
                    "type": "robots_hidden_paths",
                    "data": {"hidden_paths": hidden},
                }

        return finding

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(probe_one, entry): entry for entry in PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    # Sort by severity then path
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 99), f["path"]))

    # ── Summary stats ─────────────────────────────────────────────────────────
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    category_counts = {}
    for f in findings:
        category_counts[f["category"]] = category_counts.get(f["category"], 0) + 1

    overall = _overall_severity(findings)

    # Risk summary text
    risk_summary = _build_risk_summary(findings, overall)

    return {
        "target":           base_url,
        "total_paths_checked": len(PATHS),
        "total_found":      len(findings),
        "overall_severity": overall,
        "risk_summary":     risk_summary,
        "severity_counts":  counts,
        "category_counts":  category_counts,
        "findings":         findings,
    }


def _status_label(code: int) -> str:
    labels = {
        200: "Accessible",
        301: "Redirect (301)",
        302: "Redirect (302)",
        403: "Forbidden (exists)",
        401: "Requires Auth",
        405: "Method Not Allowed",
    }
    return labels.get(code, str(code))


def _build_risk_summary(findings: list, overall: str) -> str:
    if not findings:
        return "No sensitive paths or directories found."

    critical = [f for f in findings if f["severity"] == "Critical"]
    high     = [f for f in findings if f["severity"] == "High"]

    parts = []
    if critical:
        names = ", ".join(f["path"] for f in critical[:3])
        parts.append(f"{len(critical)} critical path(s) exposed: {names}")
    if high:
        parts.append(f"{len(high)} high-severity path(s) found")

    git_found = any("/.git" in f["path"] for f in findings)
    env_found = any("/.env" in f["path"] for f in findings)

    if git_found:
        parts.append("source code reconstruction possible via .git")
    if env_found:
        parts.append("credentials may be exposed via .env")

    return ". ".join(parts) + "." if parts else f"{len(findings)} paths found."
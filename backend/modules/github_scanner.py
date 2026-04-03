# backend/modules/github_scanner.py
# Module 4B — GitHub Repository Secret & Misconfiguration Scanner
# Uses GitHub REST API (free, no key needed for public repos)
# With token: 5000 req/hour | Without token: 60 req/hour

import re
import os
import base64
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv
import os
load_dotenv()

# ── Session ───────────────────────────────────────────────────────────────────
SESSION = requests.Session()
SESSION.headers.update({
    "Accept":     "application/vnd.github+json",
    "User-Agent": "E-WMEAP-Scanner/1.0",
})

# Optional: set GITHUB_TOKEN env variable for higher rate limits
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
if GITHUB_TOKEN:
    SESSION.headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

GITHUB_API = "https://api.github.com"

# ── Secret patterns ───────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS Access Key",       r"AKIA[0-9A-Z]{16}",                                          "Critical"),
    ("AWS Secret Key",       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",   "Critical"),
    ("Google API Key",       r"AIza[0-9A-Za-z\-_]{35}",                                    "Critical"),
    ("Google OAuth",         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",    "High"),
    ("GitHub Token",         r"gh[pousr]_[A-Za-z0-9_]{36,255}",                           "Critical"),
    ("GitHub Classic Token", r"ghp_[A-Za-z0-9]{36}",                                      "Critical"),
    ("Stripe Secret Key",    r"sk_live_[0-9a-zA-Z]{24,}",                                  "Critical"),
    ("Stripe Public Key",    r"pk_live_[0-9a-zA-Z]{24,}",                                  "Medium"),
    ("Twilio API Key",       r"SK[0-9a-fA-F]{32}",                                         "High"),
    ("SendGrid API Key",     r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",              "High"),
    ("Mailgun API Key",      r"key-[0-9a-zA-Z]{32}",                                       "High"),
    ("Private RSA Key",      r"-----BEGIN RSA PRIVATE KEY-----",                            "Critical"),
    ("Private EC Key",       r"-----BEGIN EC PRIVATE KEY-----",                             "Critical"),
    ("Private Key (Generic)",r"-----BEGIN (OPENSSH|DSA|PGP) PRIVATE KEY",                  "Critical"),
    ("JWT Token",            r"eyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_.+/=]*", "High"),
    ("Slack Token",          r"xox[baprs]-[0-9A-Za-z\-]{10,}",                            "High"),
    ("Slack Webhook",        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "High"),
    ("Firebase URL",         r"https://[a-z0-9\-]+\.firebaseio\.com",                      "Medium"),
    ("Heroku API Key",       r"[hH]eroku.{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "High"),
    ("Generic Password",     r'(?i)password\s*[=:]\s*["\'][^"\'$\s]{8,}["\']',            "High"),
    ("Generic API Key",      r'(?i)api[_\-]?key\s*[=:]\s*["\'][^"\'$\s]{8,}["\']',       "High"),
    ("Generic Secret",       r'(?i)secret[_\-]?key\s*[=:]\s*["\'][^"\'$\s]{8,}["\']',    "High"),
    ("Database URL",         r'(?i)(mysql|postgres|mongodb|redis):\/\/[^\s"\'<>]+',        "Critical"),
    ("Basic Auth in URL",    r'https?://[^:]+:[^@]+@[^\s"\']+',                           "Critical"),
    ("NPM Token",            r"npm_[A-Za-z0-9]{36}",                                       "High"),
    ("PyPI Token",           r"pypi-[A-Za-z0-9\-_]{50,}",                                 "High"),
    ("Telegram Bot Token",   r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",                          "High"),
    ("OpenAI API Key",       r"sk-[a-zA-Z0-9]{48}",                                        "Critical"),
    ("Anthropic API Key",    r"sk-ant-[a-zA-Z0-9\-_]{95,}",                               "Critical"),
    ("Cloudinary URL",       r"cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[a-z]+",              "High"),
]

# Files most likely to contain secrets — scan these first
HIGH_VALUE_FILES = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.backup", ".env.example",
    "config.py", "config.js", "config.json", "config.yaml", "config.yml",
    "settings.py", "settings.js",
    "secrets.json", "secrets.yaml", "secrets.yml",
    "credentials.json", "credentials.yaml",
    "database.yml", "database.json",
    "wp-config.php", "configuration.php",
    "application.properties", "application.yml",
    ".aws/credentials", ".aws/config",
    "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile",
    ".travis.yml", ".circleci/config.yml",
    "*.tfvars",        # Terraform variables
    "terraform.tfstate",
}

# Extensions to scan for secrets
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".json", ".yaml", ".yml",
    ".php", ".rb", ".go", ".java", ".cs",
    ".config", ".cfg", ".ini", ".conf",
    ".sh", ".bash", ".zsh",
    ".tf", ".tfvars",
    ".xml", ".properties",
    ".toml",
}

# Extensions to always skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".mp4", ".mp3", ".wav", ".pdf",
    ".zip", ".tar", ".gz", ".rar",
    ".woff", ".woff2", ".ttf", ".eot",
    ".min.js", ".min.css",
    ".lock",   # package-lock.json etc — too noisy
}

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# ── GitHub API helpers ────────────────────────────────────────────────────────

def _parse_github_url(url: str) -> tuple[str, str] | None:
    """Extract owner and repo from any GitHub URL format."""
    url = url.strip().rstrip("/")

    # Handle formats:
    # https://github.com/owner/repo
    # https://github.com/owner/repo.git
    # github.com/owner/repo
    # owner/repo

    if "github.com" in url:
        parsed = urlparse(url if "://" in url else "https://" + url)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2:
            owner = parts[0]
            repo  = parts[1].replace(".git", "")
            return owner, repo

    # Plain owner/repo format
    if "/" in url and "." not in url.split("/")[0]:
        parts = url.split("/")
        if len(parts) == 2:
            return parts[0], parts[1].replace(".git", "")

    return None


def _get_repo_info(owner: str, repo: str) -> dict:
    """Fetch repository metadata."""
    r = SESSION.get(f"{GITHUB_API}/repos/{owner}/{repo}", timeout=10)
    if r.status_code == 404:
        return {"error": f"Repository {owner}/{repo} not found or is private"}
    if r.status_code == 403:
        return {"error": "GitHub API rate limit exceeded. Set GITHUB_TOKEN env variable."}
    r.raise_for_status()
    data = r.json()
    return {
        "name":             data.get("name"),
        "full_name":        data.get("full_name"),
        "description":      data.get("description"),
        "language":         data.get("language"),
        "stars":            data.get("stargazers_count", 0),
        "forks":            data.get("forks_count", 0),
        "default_branch":   data.get("default_branch", "main"),
        "private":          data.get("private", False),
        "size_kb":          data.get("size", 0),
        "created_at":       data.get("created_at", "")[:10],
        "updated_at":       data.get("updated_at", "")[:10],
    }


def _get_file_tree(owner: str, repo: str, branch: str) -> list:
    """Get full recursive file tree using Git Trees API."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    r = SESSION.get(url, timeout=15)
    if r.status_code != 200:
        return []
    data = r.json()
    if data.get("truncated"):
        # Tree too large — still process what we got
        pass
    return [
        item for item in data.get("tree", [])
        if item.get("type") == "blob"  # only files, not directories
    ]


def _should_scan_file(path: str) -> bool:
    """Decide if a file is worth scanning for secrets."""
    filename = os.path.basename(path).lower()
    ext = os.path.splitext(filename)[1].lower()

    # Always skip binary/large files
    if ext in SKIP_EXTENSIONS:
        return False
    if filename.endswith(".min.js") or filename.endswith(".min.css"):
        return False

    # Always scan high-value files
    for hv in HIGH_VALUE_FILES:
        if filename == hv or filename.endswith(hv):
            return True

    # Scan by extension
    return ext in SCAN_EXTENSIONS


def _get_file_content(owner: str, repo: str, path: str) -> str | None:
    """Fetch decoded content of a single file via Contents API."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    try:
        r = SESSION.get(url, timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        return data.get("content", "")
    except Exception:
        return None


def _scan_content_for_secrets(content: str, filepath: str) -> list:
    """Run all secret patterns against file content."""
    findings = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # Skip comment lines and empty lines
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*", "<!--")):
            continue

        for name, pattern, severity in SECRET_PATTERNS:
            matches = re.finditer(pattern, line)
            for match in matches:
                raw_value = match.group(0)

                # Skip obvious placeholders
                if _is_placeholder(raw_value):
                    continue

                findings.append({
                    "type":        name,
                    "severity":    severity,
                    "file":        filepath,
                    "line_number": line_num,
                    "line_content": _mask_line(line.strip()),
                    "snippet":     _mask_secret(raw_value),
                    "raw_length":  len(raw_value),
                })

    return findings


def _is_placeholder(value: str) -> bool:
    """Filter out obvious placeholder/example values."""
    placeholders = [
        "your_", "YOUR_", "<your", "example", "EXAMPLE",
        "changeme", "CHANGEME", "placeholder", "PLACEHOLDER",
        "xxxxxxxx", "XXXXXXXX", "12345678", "abcdefgh",
        "test_key", "demo_key", "sample_key",
        "xxx", "XXX", "***", "...",
        "insert_", "INSERT_", "enter_", "ENTER_",
    ]
    return any(p in value for p in placeholders)


def _mask_secret(value: str) -> str:
    """Show first 6 chars and last 4 chars, mask the middle."""
    v = value.strip()
    if len(v) <= 12:
        return v[:3] + "***"
    return v[:6] + "***" + v[-4:]


def _mask_line(line: str) -> str:
    """Mask the value part of a key=value line, keep key visible."""
    # For key=value or key: value patterns
    for sep in ["=", ":"]:
        if sep in line:
            parts = line.split(sep, 1)
            if len(parts) == 2:
                key   = parts[0].strip()
                value = parts[1].strip().strip('"\'')
                if len(value) > 8:
                    masked = value[:4] + "***" + value[-2:]
                    return f"{key}{sep} {masked}"
    return line[:40] + "..." if len(line) > 40 else line


def _check_sensitive_files(owner: str, repo: str, tree: list) -> list:
    """Check if high-value sensitive files exist in the repo."""
    findings = []
    existing_paths = {item["path"].lower() for item in tree}

    sensitive_checks = [
        (".env",                  "Critical", "Environment variables file — may contain credentials"),
        (".env.production",       "Critical", "Production environment file"),
        (".env.local",            "Critical", "Local environment overrides"),
        (".aws/credentials",      "Critical", "AWS credentials file"),
        ("terraform.tfstate",     "Critical", "Terraform state — may contain resource secrets"),
        ("*.tfvars",              "High",     "Terraform variables — may contain secrets"),
        ("docker-compose.yml",    "Medium",   "Docker compose — may contain service credentials"),
        ("id_rsa",                "Critical", "SSH private key"),
        ("id_ecdsa",              "Critical", "SSH private key (ECDSA)"),
        ("*.pem",                 "High",     "PEM certificate/key file"),
        ("*.key",                 "High",     "Private key file"),
        ("database.yml",          "High",     "Database configuration"),
        ("secrets.yml",           "High",     "Secrets configuration file"),
        (".htpasswd",             "High",     "Apache password file"),
        ("wp-config.php",         "High",     "WordPress configuration"),
    ]

    for pattern, severity, description in sensitive_checks:
        if pattern.startswith("*"):
            ext = pattern[1:]
            matched = [p for p in existing_paths if p.endswith(ext)]
        else:
            matched = [p for p in existing_paths if p == pattern or p.endswith("/" + pattern)]

        for path in matched:
            findings.append({
                "type":        "Sensitive File Present",
                "severity":    severity,
                "file":        path,
                "description": description,
                "github_url":  f"https://github.com/{owner}/{repo}/blob/HEAD/{path}",
            })

    return findings


def _get_commit_history_secrets(owner: str, repo: str) -> list:
    """
    Check recent commits for accidentally committed secrets
    that may have been removed but still exist in git history.
    """
    findings = []
    try:
        r = SESSION.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/commits",
            params={"per_page": 10},
            timeout=10,
        )
        if r.status_code != 200:
            return []

        commits = r.json()
        suspicious_keywords = [
            "remove secret", "delete key", "remove password", "remove token",
            "oops", "accidentally", "secret removed", "key removed",
            "remove credentials", "fix secret", "remove api key",
        ]

        for commit in commits:
            msg = commit.get("commit", {}).get("message", "").lower()
            if any(kw in msg for kw in suspicious_keywords):
                findings.append({
                    "sha":     commit["sha"][:8],
                    "message": commit["commit"]["message"][:100],
                    "url":     commit["html_url"],
                    "date":    commit["commit"]["committer"]["date"][:10],
                    "note":    "Commit message suggests a secret was recently removed — check git history",
                })
    except Exception:
        pass
    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

def scan_github_repo(repo_url: str, max_files: int = 50) -> dict:
    """
    Scan a GitHub repository for exposed secrets and misconfigurations.
    
    Args:
        repo_url:  GitHub URL or owner/repo string
        max_files: Maximum number of files to scan (default 50, free API friendly)
    """

    # Parse URL
    parsed = _parse_github_url(repo_url)
    if not parsed:
        return {"error": f"Could not parse GitHub URL: {repo_url}. Use format: https://github.com/owner/repo"}

    owner, repo = parsed

    # Get repo info
    repo_info = _get_repo_info(owner, repo)
    if "error" in repo_info:
        return repo_info

    branch = repo_info["default_branch"]

    # Get file tree
    tree = _get_file_tree(owner, repo, branch)
    if not tree:
        return {"error": "Could not fetch repository file tree. Repository may be empty."}

    # Filter scannable files
    scannable = [
        item for item in tree
        if _should_scan_file(item["path"])
    ]

    # Sort: high-value files first
    def file_priority(item):
        fname = os.path.basename(item["path"]).lower()
        for hv in HIGH_VALUE_FILES:
            if fname == hv or fname.endswith(hv):
                return 0
        return 1

    scannable.sort(key=file_priority)
    scannable = scannable[:max_files]

    # Scan files for secrets
    all_secrets   = []
    files_scanned = []
    files_clean   = []
    api_calls     = 0

    for item in scannable:
        filepath = item["path"]
        content  = _get_file_content(owner, repo, filepath)
        api_calls += 1

        if content is None:
            continue

        secrets = _scan_content_for_secrets(content, filepath)

        if secrets:
            files_scanned.append({
                "path":          filepath,
                "secrets_found": len(secrets),
                "github_url":    f"https://github.com/{owner}/{repo}/blob/{branch}/{filepath}",
            })
            all_secrets.extend(secrets)
        else:
            files_clean.append(filepath)

    # Check for sensitive files in tree
    sensitive_files = _check_sensitive_files(owner, repo, tree)

    # Check commit history for removed secrets
    suspicious_commits = _get_commit_history_secrets(owner, repo)

    # Sort secrets by severity
    all_secrets.sort(key=lambda s: SEV_ORDER.get(s["severity"], 99))

    # Compute summary
    severity_counts = {}
    for s in all_secrets:
        severity_counts[s["severity"]] = severity_counts.get(s["severity"], 0) + 1

    overall = "None"
    if all_secrets or sensitive_files:
        all_sevs = (
            [s["severity"] for s in all_secrets] +
            [s["severity"] for s in sensitive_files]
        )
        overall = min(all_sevs, key=lambda sv: SEV_ORDER.get(sv, 99))

    rate_limit_note = (
        "Using unauthenticated API (60 req/hour). Set GITHUB_TOKEN env variable for 5000 req/hour."
        if not GITHUB_TOKEN else None
    )

    return {
        "repo_url":            f"https://github.com/{owner}/{repo}",
        "repo_info":           repo_info,
        "total_files_in_repo": len(tree),
        "total_files_scanned": len(scannable),
        "files_with_secrets":  files_scanned,
        "secrets":             all_secrets,
        "sensitive_files":     sensitive_files,
        "suspicious_commits":  suspicious_commits,
        "severity_counts":     severity_counts,
        "overall_severity":    overall,
        "api_calls_made":      api_calls,
        "rate_limit_note":     rate_limit_note,
    }
import base64
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

REQUEST_TIMEOUT_SECONDS = 10
TREE_TIMEOUT_SECONDS = 15
DEFAULT_MAX_FILES = 50
GITHUB_API = "https://api.github.com"
GITHUB_WEB_BASE = "https://github.com"
SCANNER_USER_AGENT = "E-WMEAP-Scanner/1.0"

SESSION = requests.Session()
SESSION.headers.update(
    {
        "Accept": "application/vnd.github+json",
        "User-Agent": SCANNER_USER_AGENT,
    }
)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
if GITHUB_TOKEN:
    SESSION.headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "Critical"),
    ("AWS Secret Key", r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "Critical"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "Critical"),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "High"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,255}", "Critical"),
    ("GitHub Classic Token", r"ghp_[A-Za-z0-9]{36}", "Critical"),
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", "Critical"),
    ("Stripe Public Key", r"pk_live_[0-9a-zA-Z]{24,}", "Medium"),
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", "High"),
    ("SendGrid API Key", r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}", "High"),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "High"),
    ("Private RSA Key", r"-----BEGIN RSA PRIVATE KEY-----", "Critical"),
    ("Private EC Key", r"-----BEGIN EC PRIVATE KEY-----", "Critical"),
    ("Private Key (Generic)", r"-----BEGIN (OPENSSH|DSA|PGP) PRIVATE KEY", "Critical"),
    ("JWT Token", r"eyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_.+/=]*", "High"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", "High"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "High"),
    ("Firebase URL", r"https://[a-z0-9\-]+\.firebaseio\.com", "Medium"),
    ("Heroku API Key", r"[hH]eroku.{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "High"),
    ("Generic Password", r'(?i)password\s*[=:]\s*["\'][^"\'$\s]{8,}["\']', "High"),
    ("Generic API Key", r'(?i)api[_\-]?key\s*[=:]\s*["\'][^"\'$\s]{8,}["\']', "High"),
    ("Generic Secret", r'(?i)secret[_\-]?key\s*[=:]\s*["\'][^"\'$\s]{8,}["\']', "High"),
    ("Database URL", r'(?i)(mysql|postgres|mongodb|redis):\/\/[^\s"\'<>]+', "Critical"),
    ("Basic Auth in URL", r'https?://[^:]+:[^@]+@[^\s"\']+', "Critical"),
    ("NPM Token", r"npm_[A-Za-z0-9]{36}", "High"),
    ("PyPI Token", r"pypi-[A-Za-z0-9\-_]{50,}", "High"),
    ("Telegram Bot Token", r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}", "High"),
    ("OpenAI API Key", r"sk-[a-zA-Z0-9]{48}", "Critical"),
    ("Anthropic API Key", r"sk-ant-[a-zA-Z0-9\-_]{95,}", "Critical"),
    ("Cloudinary URL", r"cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[a-z]+", "High"),
]

HIGH_VALUE_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.backup",
    ".env.example",
    "config.py",
    "config.js",
    "config.json",
    "config.yaml",
    "config.yml",
    "settings.py",
    "settings.js",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "credentials.json",
    "credentials.yaml",
    "database.yml",
    "database.json",
    "wp-config.php",
    "configuration.php",
    "application.properties",
    "application.yml",
    ".aws/credentials",
    ".aws/config",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    ".travis.yml",
    ".circleci/config.yml",
    "*.tfvars",
    "terraform.tfstate",
}

SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".env",
    ".json",
    ".yaml",
    ".yml",
    ".php",
    ".rb",
    ".go",
    ".java",
    ".cs",
    ".config",
    ".cfg",
    ".ini",
    ".conf",
    ".sh",
    ".bash",
    ".zsh",
    ".tf",
    ".tfvars",
    ".xml",
    ".properties",
    ".toml",
}

SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".mp4",
    ".mp3",
    ".wav",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".min.js",
    ".min.css",
    ".lock",
}

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SUSPICIOUS_COMMIT_KEYWORDS = [
    "remove secret",
    "delete key",
    "remove password",
    "remove token",
    "oops",
    "accidentally",
    "secret removed",
    "key removed",
    "remove credentials",
    "fix secret",
    "remove api key",
]


def _github_api_get(
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
) -> Optional[requests.Response]:
    try:
        return SESSION.get(f"{GITHUB_API}{path}", params=params, timeout=timeout)
    except requests.RequestException:
        return None


def _parse_github_url(url: str) -> Optional[Tuple[str, str]]:
    normalized_url = url.strip().rstrip("/")

    if "github.com" in normalized_url:
        parsed = urlparse(normalized_url if "://" in normalized_url else f"https://{normalized_url}")
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2:
            return parts[0], parts[1].removesuffix(".git")

    if "/" in normalized_url and "." not in normalized_url.split("/")[0]:
        parts = normalized_url.split("/")
        if len(parts) == 2:
            return parts[0], parts[1].removesuffix(".git")

    return None


def _get_repo_info(owner: str, repo: str) -> Dict[str, Any]:
    response = _github_api_get(f"/repos/{owner}/{repo}")
    if response is None:
        return {"error": "Could not reach the GitHub API."}
    if response.status_code == 404:
        return {"error": f"Repository {owner}/{repo} not found or is private"}
    if response.status_code == 403:
        return {"error": "GitHub API rate limit exceeded. Set GITHUB_TOKEN env variable."}

    response.raise_for_status()
    data = response.json()
    return {
        "name": data.get("name"),
        "full_name": data.get("full_name"),
        "description": data.get("description"),
        "language": data.get("language"),
        "stars": data.get("stargazers_count", 0),
        "forks": data.get("forks_count", 0),
        "default_branch": data.get("default_branch", "main"),
        "private": data.get("private", False),
        "size_kb": data.get("size", 0),
        "created_at": data.get("created_at", "")[:10],
        "updated_at": data.get("updated_at", "")[:10],
    }


def _get_file_tree(owner: str, repo: str, branch: str) -> List[Dict[str, Any]]:
    response = _github_api_get(
        f"/repos/{owner}/{repo}/git/trees/{branch}",
        params={"recursive": 1},
        timeout=TREE_TIMEOUT_SECONDS,
    )
    if response is None or response.status_code != 200:
        return []

    data = response.json()
    return [item for item in data.get("tree", []) if item.get("type") == "blob"]


def _is_high_value_file(filename: str) -> bool:
    return any(filename == candidate or filename.endswith(candidate) for candidate in HIGH_VALUE_FILES)


def _should_scan_file(path: str) -> bool:
    filename = os.path.basename(path).lower()
    extension = os.path.splitext(filename)[1].lower()

    if extension in SKIP_EXTENSIONS or filename.endswith((".min.js", ".min.css")):
        return False
    if _is_high_value_file(filename):
        return True
    return extension in SCAN_EXTENSIONS


def _get_file_content(owner: str, repo: str, path: str) -> Optional[str]:
    response = _github_api_get(f"/repos/{owner}/{repo}/contents/{path}")
    if response is None or response.status_code != 200:
        return None

    try:
        data = response.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        return data.get("content", "")
    except (KeyError, TypeError, ValueError):
        return None


def _scan_content_for_secrets(content: str, filepath: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*", "<!--")):
            continue

        for name, pattern, severity in SECRET_PATTERNS:
            for match in re.finditer(pattern, line):
                raw_value = match.group(0)
                if _is_placeholder(raw_value):
                    continue

                findings.append(
                    {
                        "type": name,
                        "severity": severity,
                        "file": filepath,
                        "line_number": line_number,
                        "line_content": _mask_line(stripped),
                        "snippet": _mask_secret(raw_value),
                        "raw_length": len(raw_value),
                    }
                )

    return findings


def _is_placeholder(value: str) -> bool:
    placeholders = [
        "your_",
        "YOUR_",
        "<your",
        "example",
        "EXAMPLE",
        "changeme",
        "CHANGEME",
        "placeholder",
        "PLACEHOLDER",
        "xxxxxxxx",
        "XXXXXXXX",
        "12345678",
        "abcdefgh",
        "test_key",
        "demo_key",
        "sample_key",
        "xxx",
        "XXX",
        "***",
        "...",
        "insert_",
        "INSERT_",
        "enter_",
        "ENTER_",
    ]
    return any(placeholder in value for placeholder in placeholders)


def _mask_secret(value: str) -> str:
    masked = value.strip()
    if len(masked) <= 12:
        return f"{masked[:3]}***"
    return f"{masked[:6]}***{masked[-4:]}"


def _mask_line(line: str) -> str:
    for separator in ("=", ":"):
        if separator in line:
            key, raw_value = line.split(separator, maxsplit=1)
            value = raw_value.strip().strip('"\'')
            if len(value) > 8:
                return f"{key.strip()}{separator} {value[:4]}***{value[-2:]}"
    return f"{line[:40]}..." if len(line) > 40 else line


def _check_sensitive_files(owner: str, repo: str, tree: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    existing_paths = {item["path"].lower() for item in tree}
    sensitive_checks = [
        (".env", "Critical", "Environment variables file - may contain credentials"),
        (".env.production", "Critical", "Production environment file"),
        (".env.local", "Critical", "Local environment overrides"),
        (".aws/credentials", "Critical", "AWS credentials file"),
        ("terraform.tfstate", "Critical", "Terraform state - may contain resource secrets"),
        ("*.tfvars", "High", "Terraform variables - may contain secrets"),
        ("docker-compose.yml", "Medium", "Docker compose - may contain service credentials"),
        ("id_rsa", "Critical", "SSH private key"),
        ("id_ecdsa", "Critical", "SSH private key (ECDSA)"),
        ("*.pem", "High", "PEM certificate/key file"),
        ("*.key", "High", "Private key file"),
        ("database.yml", "High", "Database configuration"),
        ("secrets.yml", "High", "Secrets configuration file"),
        (".htpasswd", "High", "Apache password file"),
        ("wp-config.php", "High", "WordPress configuration"),
    ]

    for pattern, severity, description in sensitive_checks:
        if pattern.startswith("*"):
            extension = pattern[1:]
            matched = [path for path in existing_paths if path.endswith(extension)]
        else:
            matched = [path for path in existing_paths if path == pattern or path.endswith(f"/{pattern}")]

        for path in matched:
            findings.append(
                {
                    "type": "Sensitive File Present",
                    "severity": severity,
                    "file": path,
                    "description": description,
                    "github_url": f"{GITHUB_WEB_BASE}/{owner}/{repo}/blob/HEAD/{path}",
                }
            )

    return findings


def _get_commit_history_secrets(owner: str, repo: str) -> List[Dict[str, Any]]:
    response = _github_api_get(
        f"/repos/{owner}/{repo}/commits",
        params={"per_page": 10},
    )
    if response is None or response.status_code != 200:
        return []

    findings: List[Dict[str, Any]] = []
    for commit in response.json():
        message = commit.get("commit", {}).get("message", "").lower()
        if any(keyword in message for keyword in SUSPICIOUS_COMMIT_KEYWORDS):
            findings.append(
                {
                    "sha": commit.get("sha", "")[:8],
                    "message": commit.get("commit", {}).get("message", "")[:100],
                    "url": commit.get("html_url"),
                    "date": commit.get("commit", {}).get("committer", {}).get("date", "")[:10],
                    "note": "Commit message suggests a secret was recently removed - check git history",
                }
            )
    return findings


def scan_github_repo(repo_url: str, max_files: int = DEFAULT_MAX_FILES) -> Dict[str, Any]:
    parsed = _parse_github_url(repo_url)
    if not parsed:
        return {"error": f"Could not parse GitHub URL: {repo_url}. Use format: https://github.com/owner/repo"}

    owner, repo = parsed
    repo_info = _get_repo_info(owner, repo)
    if "error" in repo_info:
        return repo_info

    tree = _get_file_tree(owner, repo, repo_info["default_branch"])
    if not tree:
        return {"error": "Could not fetch repository file tree. Repository may be empty."}

    scannable = [item for item in tree if _should_scan_file(item["path"])]
    scannable.sort(key=lambda item: 0 if _is_high_value_file(os.path.basename(item["path"]).lower()) else 1)
    scannable = scannable[:max_files]

    all_secrets: List[Dict[str, Any]] = []
    files_with_secrets: List[Dict[str, Any]] = []
    api_calls = 0
    branch = repo_info["default_branch"]

    for item in scannable:
        filepath = item["path"]
        content = _get_file_content(owner, repo, filepath)
        api_calls += 1
        if content is None:
            continue

        secrets = _scan_content_for_secrets(content, filepath)
        if secrets:
            files_with_secrets.append(
                {
                    "path": filepath,
                    "secrets_found": len(secrets),
                    "github_url": f"{GITHUB_WEB_BASE}/{owner}/{repo}/blob/{branch}/{filepath}",
                }
            )
            all_secrets.extend(secrets)

    sensitive_files = _check_sensitive_files(owner, repo, tree)
    suspicious_commits = _get_commit_history_secrets(owner, repo)
    all_secrets.sort(key=lambda finding: SEV_ORDER.get(finding["severity"], 99))

    severity_counts: Dict[str, int] = {}
    for finding in all_secrets:
        severity = finding["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    severities = [finding["severity"] for finding in all_secrets] + [finding["severity"] for finding in sensitive_files]
    overall = min(severities, key=lambda severity: SEV_ORDER.get(severity, 99)) if severities else "None"

    return {
        "repo_url": f"{GITHUB_WEB_BASE}/{owner}/{repo}",
        "repo_info": repo_info,
        "total_files_in_repo": len(tree),
        "total_files_scanned": len(scannable),
        "files_with_secrets": files_with_secrets,
        "secrets": all_secrets,
        "sensitive_files": sensitive_files,
        "suspicious_commits": suspicious_commits,
        "severity_counts": severity_counts,
        "overall_severity": overall,
        "api_calls_made": api_calls,
        "rate_limit_note": None
        if GITHUB_TOKEN
        else "Using unauthenticated API (60 req/hour). Set GITHUB_TOKEN env variable for 5000 req/hour.",
    }

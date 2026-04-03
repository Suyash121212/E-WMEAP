# backend/modules/cloud_scanner.py
# Module 7 — Cloud & Modern Stack Misconfiguration Scanner
#
# Sub-scanners:
#   A. S3 Bucket Enumeration & Public Access
#   B. Subdomain Takeover Detection (crt.sh + DNS CNAME analysis)
#   C. Exposed Cloud Services (Docker, K8s, Elasticsearch, Jenkins, etc.)

import re
import xml.etree.ElementTree as ET
import socket
import requests
import dns.resolver
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; E-WMEAP-Scanner/1.0)",
})
SESSION.max_redirects = 2

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}

# ══════════════════════════════════════════════════════════════════════════════
# A. S3 BUCKET SCANNER
# ══════════════════════════════════════════════════════════════════════════════

S3_BUCKET_SUFFIXES = [
    "",              # exact domain name
    "-backup",
    "-backups",
    "-assets",
    "-static",
    "-uploads",
    "-upload",
    "-media",
    "-files",
    "-data",
    "-prod",
    "-production",
    "-dev",
    "-development",
    "-staging",
    "-test",
    "-public",
    "-private",
    "-logs",
    "-cdn",
    "-storage",
    "-images",
    "-img",
    "-docs",
    "-config",
    "-secrets",
    "-env",
    "-dump",
]

def _extract_base_name(domain: str) -> str:
    """
    Extract usable bucket name from domain.
    e.g. www.example.com → example
         api.myapp.io    → myapp
    """
    domain = domain.lower().strip()
    # Remove www / api / mail prefixes
    for prefix in ("www.", "api.", "mail.", "app.", "dev.", "staging."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    # Remove TLD
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[0]
    return domain


def _check_s3_bucket(bucket_name: str) -> dict | None:
    """
    Check a single S3 bucket for existence and public access.
    No AWS credentials needed — all public HTTP.
    """
    url = f"https://{bucket_name}.s3.amazonaws.com"
    result = {
        "bucket_name": bucket_name,
        "url":         url,
        "exists":      False,
        "public_read": False,
        "files":       [],
        "file_count":  0,
        "severity":    "None",
        "status_code": None,
        "finding":     None,
    }

    try:
        r = SESSION.head(url, timeout=8)
        result["status_code"] = r.status_code

        if r.status_code == 404:
            return None  # Bucket does not exist

        if r.status_code == 403:
            # Bucket exists but access is denied — still a finding
            result["exists"]   = True
            result["severity"] = "Medium"
            result["finding"]  = (
                f"Bucket '{bucket_name}' exists but public access is blocked. "
                "Confirms AWS S3 usage — may be misconfigured with weak ACLs."
            )
            return result

        if r.status_code == 200:
            result["exists"]      = True
            result["public_read"] = True

            # List bucket contents
            list_url = f"{url}/?list-type=2&max-keys=50"
            lr = SESSION.get(list_url, timeout=10)
            if lr.status_code == 200:
                files, sensitive = _parse_s3_listing(lr.text)
                result["files"]       = files[:30]
                result["file_count"]  = len(files)
                result["sensitive_files"] = sensitive

                result["severity"] = "Critical" if sensitive else "High"
                result["finding"]  = (
                    f"Bucket '{bucket_name}' is PUBLICLY READABLE. "
                    f"{len(files)} files listed."
                    + (f" {len(sensitive)} sensitive file(s) detected." if sensitive else "")
                )
            else:
                result["severity"] = "High"
                result["finding"]  = f"Bucket '{bucket_name}' is publicly accessible (HTTP 200) but listing is disabled."

            return result

    except requests.exceptions.ConnectionError:
        return None  # Bucket definitely does not exist
    except Exception:
        return None

    return None


def _parse_s3_listing(xml_content: str) -> tuple[list, list]:
    """Parse S3 XML listing response, extract file keys."""
    files     = []
    sensitive = []

    SENSITIVE_PATTERNS = [
        r"\.env", r"\.sql", r"\.db", r"backup", r"credential",
        r"password", r"secret", r"private", r"\.pem", r"\.key",
        r"config", r"\.tar", r"\.zip", r"dump", r"token",
        r"\.csv", r"\.json", r"id_rsa",
    ]

    try:
        root = ET.fromstring(xml_content)
        ns   = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}

        for content in root.findall(".//s3:Contents", ns):
            key  = content.findtext("s3:Key", default="", namespaces=ns)
            size = content.findtext("s3:Size", default="0", namespaces=ns)
            if key:
                files.append({"key": key, "size": int(size)})
                if any(re.search(p, key, re.IGNORECASE) for p in SENSITIVE_PATTERNS):
                    sensitive.append(key)
    except Exception:
        pass

    return files, sensitive


def scan_s3(domain: str) -> dict:
    """Enumerate and check likely S3 bucket names for a target domain."""
    base_name = _extract_base_name(domain)

    # Build candidate list
    candidates = []
    # Use both full domain and base name as prefix
    for prefix in [base_name, domain.replace(".", "-"), domain.split(".")[0]]:
        for suffix in S3_BUCKET_SUFFIXES:
            name = f"{prefix}{suffix}".lower()
            # S3 bucket name rules: 3-63 chars, lowercase, no consecutive dots
            name = re.sub(r"[^a-z0-9\-]", "-", name)
            name = re.sub(r"-{2,}", "-", name).strip("-")
            if 3 <= len(name) <= 63 and name not in candidates:
                candidates.append(name)

    candidates = candidates[:60]  # cap to avoid hammering

    findings = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(_check_s3_bucket, name): name for name in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 99))
    overall = findings[0]["severity"] if findings else "None"

    return {
        "buckets_checked": len(candidates),
        "buckets_found":   len(findings),
        "overall_severity": overall,
        "findings":        findings,
        "summary":         _s3_summary(findings),
    }


def _s3_summary(findings: list) -> str:
    if not findings:
        return "No S3 buckets found for this target."
    public = [f for f in findings if f["public_read"]]
    exists = [f for f in findings if f["exists"] and not f["public_read"]]
    parts  = []
    if public:
        parts.append(f"{len(public)} publicly readable bucket(s) found")
    if exists:
        parts.append(f"{len(exists)} private bucket(s) confirmed to exist")
    return ". ".join(parts) + "."


# ══════════════════════════════════════════════════════════════════════════════
# B. SUBDOMAIN TAKEOVER SCANNER
# ══════════════════════════════════════════════════════════════════════════════

# CNAME fingerprints for known vulnerable services
# Format: (service_name, cname_pattern, fingerprint_in_body, severity)
TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages",      r"github\.io",           "There isn't a GitHub Pages site here",      "Critical"),
    ("Heroku",            r"herokudns\.com|heroku\.com", "No such app",                         "Critical"),
    ("Netlify",           r"netlify\.app|netlify\.com",  "Not Found",                           "Critical"),
    ("Vercel",            r"vercel\.app|vercel\.com",    "The deployment could not be found",   "Critical"),
    ("AWS S3",            r"s3\.amazonaws\.com|s3-website", "NoSuchBucket",                    "Critical"),
    ("AWS CloudFront",    r"cloudfront\.net",        "Bad request",                             "High"),
    ("Azure",             r"azurewebsites\.net",     "404 Web Site not found",                  "Critical"),
    ("Azure Blob",        r"blob\.core\.windows\.net","BlobNotFound",                           "Critical"),
    ("Shopify",           r"myshopify\.com",         "Sorry, this shop is currently unavailable","High"),
    ("Fastly",            r"fastly\.net",            "Fastly error: unknown domain",            "Critical"),
    ("Ghost",             r"ghost\.io",              "The thing you were looking for is no longer here", "High"),
    ("Cargo",             r"cargo\.site",            "If you're moving your domain away",       "Medium"),
    ("Tumblr",            r"tumblr\.com",            "Whatever you were looking for doesn't live here", "High"),
    ("WordPress",         r"wordpress\.com",         "Do you want to register",                 "High"),
    ("Zendesk",           r"zendesk\.com",           "Help Center Closed",                      "High"),
    ("Freshdesk",         r"freshdesk\.com",         "There is no helpdesk here",               "Medium"),
    ("Pingdom",           r"pingdom\.com",           "This public report page has not been activated", "Low"),
    ("Campaign Monitor",  r"createsend\.com",        "Double check the URL",                    "Medium"),
    ("HubSpot",           r"hubspot\.net|hs-sites\.com", "Domain not found",                   "High"),
    ("Unbounce",          r"unbouncepages\.com",     "The requested URL was not found",         "Medium"),
    ("Surge",             r"surge\.sh",              "project not found",                       "High"),
    ("Fly.io",            r"fly\.dev",               "404 Not Found",                           "High"),
    ("Render",            r"onrender\.com",          "Service not found",                       "High"),
    ("Railway",           r"railway\.app",           "Application not found",                   "High"),
    ("Webflow",           r"webflow\.io",            "The page you are looking for doesn't exist", "High"),
    ("Intercom",          r"intercom\.io",           "This page is reserved for future use",    "Medium"),
    ("Desk.com",          r"desk\.com",              "Please try again or try Desk.com free",   "Medium"),
    ("Tilda",             r"tilda\.ws",              "Please renew your subscription",          "Low"),
]


def _get_subdomains_crtsh(domain: str) -> list:
    """
    Fetch subdomains from crt.sh certificate transparency logs.
    Free, no API key needed.
    """
    subdomains = set()
    try:
        r = SESSION.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception:
        pass
    return list(subdomains)


def _get_subdomains_hackertarget(domain: str) -> list:
    """
    Fetch subdomains from HackerTarget API.
    Free tier: 100 queries/day, no key needed.
    """
    subdomains = []
    try:
        r = SESSION.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=10,
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                if "," in line:
                    subdomain = line.split(",")[0].strip().lower()
                    if subdomain.endswith(f".{domain}"):
                        subdomains.append(subdomain)
    except Exception:
        pass
    return subdomains


def _get_cname(subdomain: str) -> str | None:
    """Resolve CNAME record for a subdomain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout  = 4
        resolver.lifetime = 4
        answers = resolver.resolve(subdomain, "CNAME")
        if answers:
            return str(answers[0].target).rstrip(".").lower()
    except Exception:
        pass
    return None


def _check_takeover(subdomain: str) -> dict | None:
    """
    Check if a subdomain is vulnerable to takeover.
    Steps:
      1. Resolve CNAME
      2. Match against known vulnerable service patterns
      3. Fetch the page body to confirm fingerprint
    """
    cname = _get_cname(subdomain)
    if not cname:
        return None

    for service, cname_pattern, body_fingerprint, severity in TAKEOVER_FINGERPRINTS:
        if re.search(cname_pattern, cname, re.IGNORECASE):
            # CNAME matches a known service — now check if the service
            # shows a "not found" fingerprint (unclaimed)
            try:
                r = SESSION.get(
                    f"http://{subdomain}",
                    timeout=8,
                    allow_redirects=True,
                )
                body = r.text
                if body_fingerprint.lower() in body.lower():
                    return {
                        "subdomain":   subdomain,
                        "cname":       cname,
                        "service":     service,
                        "severity":    severity,
                        "fingerprint": body_fingerprint,
                        "status_code": r.status_code,
                        "exploitable": True,
                        "description": (
                            f"Subdomain {subdomain} has a CNAME pointing to {service} ({cname}) "
                            f"but the service is unclaimed. An attacker can register this service "
                            f"and take control of this subdomain."
                        ),
                        "technique": {
                            "name":  f"Subdomain Takeover via {service}",
                            "steps": [
                                f"Subdomain {subdomain} → CNAME → {cname}",
                                f"CNAME points to {service}",
                                f"Service shows fingerprint: '{body_fingerprint}'",
                                f"Sign up for {service} and claim '{cname}'",
                                f"You now control {subdomain} — can serve content, steal cookies",
                                "If main site has CORS trusting this subdomain → full CORS attack",
                            ],
                        },
                    }
                # CNAME matches but fingerprint not present — service is claimed
                # Still report as informational
                return {
                    "subdomain":   subdomain,
                    "cname":       cname,
                    "service":     service,
                    "severity":    "Low",
                    "fingerprint": None,
                    "status_code": r.status_code,
                    "exploitable": False,
                    "description": (
                        f"Subdomain {subdomain} CNAME points to {service}. "
                        "Service appears claimed — monitor for future dangling CNAME."
                    ),
                    "technique": {},
                }
            except Exception:
                # Can't reach the subdomain at all — may still be vulnerable
                return {
                    "subdomain":   subdomain,
                    "cname":       cname,
                    "service":     service,
                    "severity":    "Medium",
                    "fingerprint": None,
                    "status_code": None,
                    "exploitable": False,
                    "description": (
                        f"Subdomain {subdomain} has dangling CNAME to {service} "
                        "but could not be reached to confirm takeover."
                    ),
                    "technique": {},
                }
    return None


def scan_subdomains(domain: str) -> dict:
    """Enumerate subdomains and check each for takeover vulnerability."""

    # Gather subdomains from both sources
    crtsh_subs  = _get_subdomains_crtsh(domain)
    ht_subs     = _get_subdomains_hackertarget(domain)

    all_subs = list({*crtsh_subs, *ht_subs})
    all_subs = [s for s in all_subs if s != domain][:80]  # cap at 80

    findings = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(_check_takeover, sub): sub for sub in all_subs}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 99))
    exploitable = [f for f in findings if f["exploitable"]]
    overall     = findings[0]["severity"] if findings else "None"

    return {
        "domain":             domain,
        "subdomains_found":   len(all_subs),
        "subdomains_list":    sorted(all_subs)[:50],
        "takeover_findings":  findings,
        "exploitable_count":  len(exploitable),
        "overall_severity":   overall,
        "sources": {
            "crtsh":       len(crtsh_subs),
            "hackertarget": len(ht_subs),
        },
        "summary": _subdomain_summary(exploitable, all_subs),
    }


def _subdomain_summary(exploitable: list, all_subs: list) -> str:
    if not exploitable:
        return f"No subdomain takeover vulnerabilities found across {len(all_subs)} discovered subdomains."
    return (
        f"{len(exploitable)} subdomain(s) vulnerable to takeover: "
        + ", ".join(f["subdomain"] for f in exploitable[:3])
        + ("..." if len(exploitable) > 3 else "")
        + "."
    )


# ══════════════════════════════════════════════════════════════════════════════
# C. EXPOSED CLOUD SERVICES SCANNER
# ══════════════════════════════════════════════════════════════════════════════

# (path, service, severity, description, verify_fn_name, ports_to_try)
CLOUD_SERVICE_CHECKS = [
    # Docker
    ("/version",            "Docker API",              "Critical",
     "Unauthenticated Docker API — full host takeover possible",
     "docker",    [2375, 2376]),

    ("/info",               "Docker API (info)",       "Critical",
     "Docker daemon info endpoint exposed",
     "docker",    [2375, 2376]),

    # Kubernetes
    ("/api/v1",             "Kubernetes API",          "Critical",
     "Kubernetes API server exposed — cluster control possible",
     "kubernetes", [8001, 6443, 443]),

    ("/api/v1/namespaces",  "Kubernetes Namespaces",   "Critical",
     "Kubernetes namespace listing accessible without auth",
     "kubernetes", [8001, 6443]),

    # Elasticsearch
    ("/_cat/indices",       "Elasticsearch",           "Critical",
     "Elasticsearch index listing — all data readable without auth",
     "elastic",   [9200, 9300]),

    ("/_cluster/health",    "Elasticsearch Health",    "High",
     "Elasticsearch cluster health exposed",
     "elastic",   [9200]),

    # Jenkins
    ("/script",             "Jenkins Script Console",  "Critical",
     "Jenkins Groovy script console — remote code execution possible",
     "jenkins",   [8080, 8443]),

    ("/api/json",           "Jenkins API",             "High",
     "Jenkins API exposed — job/build information accessible",
     "jenkins",   [8080]),

    # Prometheus
    ("/metrics",            "Prometheus Metrics",      "Medium",
     "Prometheus metrics endpoint — internal system data exposed",
     "prometheus", [9090, 9091]),

    ("/api/v1/targets",     "Prometheus Targets",      "High",
     "Prometheus scrape targets — internal service map exposed",
     "prometheus", [9090]),

    # Grafana
    ("/api/health",         "Grafana",                 "Medium",
     "Grafana health endpoint exposed",
     "grafana",   [3000]),

    ("/api/datasources",    "Grafana Datasources",     "Critical",
     "Grafana datasources exposed — may contain database credentials",
     "grafana",   [3000]),

    # Swagger / API Docs
    ("/swagger-ui.html",    "Swagger UI",              "Medium",
     "Swagger UI accessible — full API documentation and test interface exposed",
     "swagger",   [80, 443, 8080]),

    ("/swagger-ui/",        "Swagger UI",              "Medium",
     "Swagger UI directory accessible",
     "swagger",   [80, 443, 8080]),

    ("/api-docs",           "API Docs",                "Medium",
     "API documentation exposed",
     "swagger",   [80, 443, 8080]),

    ("/openapi.json",       "OpenAPI Spec",            "Medium",
     "OpenAPI specification exposed — full API structure readable",
     "swagger",   [80, 443, 8080]),

    ("/v2/api-docs",        "Swagger v2 Docs",         "Medium",
     "Swagger v2 API documentation exposed",
     "swagger",   [80, 443, 8080]),

    # Redis (HTTP probe — limited but catches misconfigured HTTP proxies)
    ("/",                   "Redis HTTP Proxy",        "Critical",
     "Possible Redis HTTP proxy exposed — check port 6379 directly",
     "redis",     [6379]),

    # Consul
    ("/v1/catalog/services","Consul",                  "High",
     "Consul service catalog exposed — internal service discovery data readable",
     "consul",    [8500]),

    ("/v1/kv/",             "Consul KV",               "Critical",
     "Consul key-value store exposed — may contain secrets and credentials",
     "consul",    [8500]),

    # etcd (Kubernetes backing store)
    ("/v3/keys",            "etcd",                    "Critical",
     "etcd key-value store exposed — Kubernetes secrets accessible",
     "etcd",      [2379, 2380]),

    # RabbitMQ
    ("/api/overview",       "RabbitMQ Management",     "High",
     "RabbitMQ management API exposed — message queue data and credentials",
     "rabbitmq",  [15672]),

    # Apache Airflow
    ("/api/v1/dags",        "Apache Airflow",          "High",
     "Airflow DAG API exposed — pipeline definitions and connections readable",
     "airflow",   [8080]),

    # Jupyter Notebook
    ("/api/kernels",        "Jupyter Notebook",        "Critical",
     "Jupyter Notebook API exposed — remote code execution possible",
     "jupyter",   [8888, 8889]),

    # phpMyAdmin
    ("/phpmyadmin/",        "phpMyAdmin",              "Critical",
     "phpMyAdmin exposed — direct database management interface",
     "phpmyadmin",[80, 443]),

    ("/pma/",               "phpMyAdmin (pma)",        "Critical",
     "phpMyAdmin accessible via /pma/",
     "phpmyadmin",[80, 443]),
]

# Content verification — what a genuine response contains
SERVICE_VERIFIERS = {
    "docker":      ["ApiVersion", "Version", "Os", "Arch", "KernelVersion"],
    "kubernetes":  ["apiVersion", "kind", "namespaces", "groupVersion"],
    "elastic":     ["health", "status", "index", "epoch", "docs"],
    "jenkins":     ["jenkins", "hudson", "script", "Jobs", "executors"],
    "prometheus":  ["# HELP", "# TYPE", "prometheus", "targets", "up{"],
    "grafana":     ["grafana", "database", "version", "commit"],
    "swagger":     ["swagger", "openapi", "paths", "Swagger UI", "api-docs"],
    "redis":       ["redis_version", "connected_clients", "PONG"],
    "consul":      ["ServiceName", "Node", "datacenter", "Services"],
    "etcd":        ["etcdserver", "revision", "cluster_id"],
    "rabbitmq":    ["rabbitmq_version", "erlang_version", "message_stats"],
    "airflow":     ["dag_id", "is_active", "file_token"],
    "jupyter":     ["kernel_id", "execution_state", "kernel_name"],
    "phpmyadmin":  ["phpMyAdmin", "pmahomme", "phpmyadmin"],
}


def _check_cloud_service(base_url: str, path: str, service: str,
                          severity: str, description: str,
                          verifier_key: str, ports: list) -> dict | None:
    """
    Check if a cloud service endpoint is exposed on the target.
    Tries both the standard URL and alternative ports.
    """
    parsed   = urlparse(base_url)
    hostname = parsed.netloc.split(":")[0]
    verifiers = SERVICE_VERIFIERS.get(verifier_key, [])

    urls_to_try = [base_url.rstrip("/") + path]

    # Also try with explicit ports
    for port in ports:
        if port not in (80, 443):
            urls_to_try.append(f"http://{hostname}:{port}{path}")

    for url in urls_to_try:
        try:
            r = SESSION.get(url, timeout=6, allow_redirects=False)
            if r.status_code in (404, 301, 302, 307, 308):
                continue
            if r.status_code >= 500:
                continue

            body = r.text[:3000]

            # Verify content matches expected service
            if verifiers:
                matched = sum(1 for v in verifiers if v.lower() in body.lower())
                if matched == 0:
                    continue  # Not the right service

            return {
                "service":     service,
                "path":        path,
                "url":         url,
                "severity":    severity,
                "description": description,
                "status_code": r.status_code,
                "content_preview": body[:300],
                "verifier_key": verifier_key,
                "technique":   _cloud_technique(verifier_key, url, service),
                "remediation": _cloud_remediation(verifier_key),
            }
        except Exception:
            continue

    return None


def _cloud_technique(service_key: str, url: str, service_name: str) -> dict:
    techniques = {
        "docker": {
            "name":  "Docker API Remote Code Execution",
            "steps": [
                f"Unauthenticated Docker API at {url}",
                "List running containers: GET /containers/json",
                "Create a new container mounting host filesystem: POST /containers/create",
                '{"Image":"ubuntu","Binds":["/:/host"],"Cmd":["cat","/host/etc/shadow"]}',
                "Start container: POST /containers/{id}/start",
                "Read output: GET /containers/{id}/logs — full host filesystem access",
            ],
            "impact": "Full host takeover — read/write any file on the host OS",
        },
        "kubernetes": {
            "name":  "Kubernetes API Cluster Takeover",
            "steps": [
                f"Unauthenticated Kubernetes API at {url}",
                "List all pods: GET /api/v1/pods",
                "List secrets: GET /api/v1/namespaces/default/secrets",
                "Create privileged pod with host volume mount",
                "Exec into pod: POST /api/v1/namespaces/default/pods/{name}/exec",
                "Full cluster and host node compromise",
            ],
            "impact": "Full Kubernetes cluster takeover — all nodes, all secrets, all workloads",
        },
        "elastic": {
            "name":  "Elasticsearch Data Exfiltration",
            "steps": [
                f"Unauthenticated Elasticsearch at {url}",
                "List all indices: GET /_cat/indices",
                "Dump all data from any index: GET /{index}/_search?size=10000",
                "No credentials required — all data directly readable",
            ],
            "impact": "Complete database dump without any credentials",
        },
        "jenkins": {
            "name":  "Jenkins Groovy Console RCE",
            "steps": [
                f"Jenkins Script Console at {url}",
                'Execute Groovy: println "id".execute().text',
                "Runs as Jenkins service account on the host",
                "Read files, execute commands, pivot to other systems",
            ],
            "impact": "Remote code execution on Jenkins server — full host compromise",
        },
        "grafana": {
            "name":  "Grafana Credential Extraction",
            "steps": [
                f"Grafana datasources API at {url}",
                "GET /api/datasources — returns all configured data sources",
                "Response includes database hostnames, usernames, and passwords",
                "Use credentials to directly access backing databases",
            ],
            "impact": "Database credentials for all connected data sources",
        },
        "jupyter": {
            "name":  "Jupyter Notebook RCE",
            "steps": [
                f"Jupyter API at {url}",
                "POST /api/kernels — create new execution kernel",
                "POST /api/kernels/{id}/channels — WebSocket connection",
                "Execute arbitrary Python code in kernel",
                "Full access to server filesystem and environment",
            ],
            "impact": "Remote code execution with Jupyter server process privileges",
        },
    }
    default = {
        "name":  f"{service_name} Exposure",
        "steps": [f"Service {service_name} accessible at {url} without authentication"],
        "impact": "Internal service data readable without credentials",
    }
    return techniques.get(service_key, default)


def _cloud_remediation(service_key: str) -> str:
    remediations = {
        "docker":      "Bind Docker API to localhost only (--host unix:///var/run/docker.sock). If TCP is required, enable TLS authentication.",
        "kubernetes":  "Disable anonymous authentication. Enable RBAC. Never expose API server directly to internet.",
        "elastic":     "Enable X-Pack security. Require authentication. Bind to localhost or private network only.",
        "jenkins":     "Restrict Script Console to admins only. Enable authentication. Place behind VPN or private network.",
        "prometheus":  "Restrict /metrics endpoint to internal network only. Add authentication middleware.",
        "grafana":     "Require authentication for all endpoints. Restrict datasource API to admin users only.",
        "swagger":     "Disable Swagger UI in production environments. If needed, protect with authentication.",
        "consul":      "Enable ACL system. Bind to private network. Never expose to public internet.",
        "etcd":        "Enable TLS and client certificate authentication. Never expose to public internet.",
        "jupyter":     "Require token or password authentication. Bind to localhost. Never expose publicly.",
        "phpmyadmin":  "Restrict phpMyAdmin to admin IP ranges only. Consider removing entirely from production.",
    }
    return remediations.get(service_key, "Restrict this service to internal network access only. Add authentication.")


def scan_cloud_services(base_url: str) -> dict:
    """Check for exposed cloud services and infrastructure management interfaces."""
    findings = []

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(
                _check_cloud_service,
                base_url, path, service, severity, description, verifier, ports
            ): (service, path)
            for path, service, severity, description, verifier, ports
            in CLOUD_SERVICE_CHECKS
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                # Deduplicate by service+verifier
                existing = next(
                    (f for f in findings
                     if f["verifier_key"] == result["verifier_key"]
                     and f["severity"] == result["severity"]),
                    None
                )
                if not existing:
                    findings.append(result)

    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 99))
    overall = findings[0]["severity"] if findings else "None"

    return {
        "services_checked": len(CLOUD_SERVICE_CHECKS),
        "findings":         findings,
        "overall_severity": overall,
        "summary":          _services_summary(findings),
    }


def _services_summary(findings: list) -> str:
    if not findings:
        return "No exposed cloud services or infrastructure interfaces detected."
    critical = [f for f in findings if f["severity"] == "Critical"]
    high     = [f for f in findings if f["severity"] == "High"]
    parts    = []
    if critical:
        names = ", ".join(f["service"] for f in critical[:3])
        parts.append(f"{len(critical)} critical service(s) exposed: {names}")
    if high:
        parts.append(f"{len(high)} high-severity service(s) found")
    return ". ".join(parts) + "."


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def scan_cloud(url: str) -> dict:
    """Run all three cloud misconfiguration sub-scanners."""
    parsed   = urlparse(url)
    domain   = parsed.netloc or parsed.path
    domain   = domain.split(":")[0]  # strip port
    base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else url

    s3_result       = scan_s3(domain)
    subdomain_result= scan_subdomains(domain)
    services_result = scan_cloud_services(base_url)

    all_sevs = [
        r.get("overall_severity", "None")
        for r in (s3_result, subdomain_result, services_result)
        if r.get("overall_severity", "None") != "None"
    ]
    overall = min(all_sevs, key=lambda s: SEV_ORDER.get(s, 99)) if all_sevs else "None"

    total = (
        len(s3_result.get("findings", [])) +
        len(subdomain_result.get("takeover_findings", [])) +
        len(services_result.get("findings", []))
    )

    return {
        "target":          base_url,
        "domain":          domain,
        "overall_severity": overall,
        "total_findings":  total,
        "s3":              s3_result,
        "subdomains":      subdomain_result,
        "services":        services_result,
    }
import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict
from urllib.parse import urlparse

import aiohttp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_CVE_RESULTS = 5
UNKNOWN_VERSION = "unknown"
OPEN_STATE = "open"
UNKNOWN_SERVICE = "unknown"
NMAP_ARGUMENTS_TEMPLATE = "-sV -p {ports} --open -T4"
DEFAULT_HTTP_TIMEOUT_SECONDS = 10
NVD_HTTP_TIMEOUT_SECONDS = 15


class DangerousPortInfo(TypedDict):
    service: str
    risk: str
    reason: str


class CVERecord(TypedDict, total=False):
    id: str
    cve_id: str
    description: str
    cvss_score: float
    cvss_severity: str
    source: str


class CVEEnrichment(TypedDict):
    cves: List[CVERecord]
    total_cves: int
    highest_cvss: float
    highest_severity: str
    has_exploit: bool
    has_metasploit: bool
    exploit_available: bool


class PortScanResult(TypedDict, total=False):
    port: int
    protocol: str
    service: str
    version: str
    product: str
    state: Literal["open"]
    dangerous: bool
    dangerous_info: DangerousPortInfo
    cve_enrichment: CVEEnrichment
    display_message: str


class ScanSummary(TypedDict, total=False):
    target: str
    scanned_ports: List[int]
    open_ports: List[PortScanResult]
    total_open: int
    dangerous_ports: List[PortScanResult]
    risk_score: float
    risk_level: str
    scan_time: str
    error: str

# Dangerous ports configuration
DANGEROUS_PORTS: Dict[int, DangerousPortInfo] = {
    21: {"service": "FTP", "risk": "High", "reason": "Plaintext credentials, anonymous login common"},
    22: {"service": "SSH", "risk": "Medium", "reason": "Brute-force target if password auth enabled"},
    3306: {"service": "MySQL", "risk": "Critical", "reason": "Database directly internet-accessible"},
    5432: {"service": "PostgreSQL", "risk": "Critical", "reason": "Database directly internet-accessible"},
    6379: {"service": "Redis", "risk": "Critical", "reason": "No auth by default, remote code execution known"},
    27017: {"service": "MongoDB", "risk": "Critical", "reason": "No auth by default in older versions"},
    9200: {"service": "Elasticsearch", "risk": "Critical", "reason": "Data dump without credentials"},
    2375: {"service": "Docker API", "risk": "Critical", "reason": "Unauthenticated Docker = full host takeover"},
    8500: {"service": "Consul", "risk": "High", "reason": "Service mesh control plane exposed"},
}

SCAN_PORTS = [21, 22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 9200, 2375]
CPE_MAPPINGS = {
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "mysql": ("mysql", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elasticsearch", "elasticsearch"),
    "docker": ("docker", "docker"),
    "openssh": ("openbsd", "openssh"),
    "node": ("nodejs", "node.js"),
    "express": ("expressjs", "express"),
    "flask": ("palletsprojects", "flask"),
    "golang": ("golang", "go"),
}
KNOWN_EXPLOITS = {
    "apache": {
        "2.4.49": "CVE-2021-41773 - Path Traversal/RCE",
        "2.4.50": "CVE-2021-42013 - Path Traversal/RCE",
    },
    "nginx": {
        "1.20.0": "CVE-2021-23017 - Request smuggling",
    },
    "openssh": {
        "8.5": "CVE-2021-28041 - Privilege escalation",
        "9.0": "CVE-2022-31107 - Remote code execution",
    },
    "redis": {
        "5.0.0": "CVE-2022-0543 - Lua sandbox escape",
    },
    "docker": {
        "19.03.0": "CVE-2019-5736 - Container escape",
    },
    "mysql": {
        "8.0.0": "CVE-2023-21912 - DoS vulnerability",
    },
}


class CVECache:
    """In-memory cache for CVE data."""

    def __init__(self) -> None:
        self.cache: Dict[str, CVEEnrichment] = {}

    def get_cached_cve(self, key: str) -> Optional[CVEEnrichment]:
        return self.cache.get(key)

    def cache_cve_data(self, key: str, data: CVEEnrichment) -> None:
        self.cache[key] = data
        logger.info("Cached CVE data for: %s", key)


class CVEFetcher:
    """Fetch CVE data from multiple free APIs."""

    def __init__(self, cache: CVECache) -> None:
        self.cache = cache
        self.session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()
        self.session = None

    async def _request_json(
        self,
        method: str,
        url: str,
        *,
        request_label: str,
        timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
        **kwargs: Any,
    ) -> Optional[Any]:
        session = await self._ensure_session()

        try:
            async with session.request(
                method,
                url,
                timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                **kwargs,
            ) as response:
                if response.status != 200:
                    logger.warning("%s request failed with status %s", request_label, response.status)
                    return None
                return await response.json()
        except Exception:
            logger.exception("%s request failed", request_label)
            return None

    def build_cpe_string(self, product: str, version: str) -> str:
        """Build a best-effort CPE string from product and version."""
        normalized = product.lower().replace(" ", "_")
        vendor, product_name = normalized, normalized

        for key, mapping in CPE_MAPPINGS.items():
            if key in normalized:
                vendor, product_name = mapping
                break

        version_clean = version.replace("v", "").replace("version", "").strip()
        return f"cpe:2.3:a:{vendor}:{product_name}:{version_clean}:*:*:*:*:*:*:*"

    async def fetch_from_nvd(self, cpe_string: str) -> List[CVERecord]:
        """Fetch CVEs from the NVD API."""
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        data = await self._request_json(
            "GET",
            url,
            request_label=f"NVD lookup for {cpe_string}",
            timeout_seconds=NVD_HTTP_TIMEOUT_SECONDS,
            params={"cpeName": cpe_string, "resultsPerPage": MAX_CVE_RESULTS},
        )
        if not data:
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cvss_score, cvss_severity = self._extract_nvd_metrics(cve_data.get("metrics", {}))

            cves.append(
                {
                    "id": cve_data.get("id", ""),
                    "description": self._extract_description(cve_data.get("descriptions", [])),
                    "cvss_score": cvss_score,
                    "cvss_severity": cvss_severity,
                    "source": "NVD",
                }
            )

        return cves

    async def fetch_from_circl(self, product: str, version: str) -> List[CVERecord]:
        """Fetch CVEs from cve.circl.lu."""
        product_clean = product.lower().split()[0]
        url = f"https://cve.circl.lu/api/search/{product_clean}/{version}"
        data = await self._request_json(
            "GET",
            url,
            request_label=f"CIRCL lookup for {product} {version}",
        )
        if not isinstance(data, list):
            return []

        cves = []
        for cve in data[:MAX_CVE_RESULTS]:
            cvss_score = self._safe_float(cve.get("cvss"))
            cves.append(
                {
                    "id": cve.get("id", ""),
                    "description": str(cve.get("summary", ""))[:250],
                    "cvss_score": cvss_score,
                    "cvss_severity": self._get_severity_from_score(cvss_score),
                    "source": "CIRCL",
                }
            )
        return cves

    async def fetch_from_osv(self, package: str, version: str) -> List[CVERecord]:
        """Fetch CVEs from OSV.dev."""
        data = await self._request_json(
            "POST",
            "https://api.osv.dev/v1/query",
            request_label=f"OSV lookup for {package} {version}",
            json={
                "package": {
                    "name": package,
                    "ecosystem": "Debian",
                },
                "version": version,
            },
        )
        if not data:
            return []

        cves = []
        for vuln in data.get("vulns", [])[:MAX_CVE_RESULTS]:
            cvss_score = self._extract_osv_score(vuln)
            cves.append(
                {
                    "id": vuln.get("id", ""),
                    "description": str(vuln.get("summary", ""))[:250],
                    "cvss_score": cvss_score,
                    "cvss_severity": self._get_severity_from_score(cvss_score),
                    "source": "OSV.dev",
                }
            )

        return cves

    async def fetch_github_advisory(self, product: str) -> List[CVERecord]:
        """Fetch advisories from GitHub's advisory database."""
        url = f"https://api.github.com/advisories?ecosystem=OTHER&cve_id=&severity=&keyword={product}"
        data = await self._request_json(
            "GET",
            url,
            request_label=f"GitHub Advisory lookup for {product}",
            headers={"Accept": "application/vnd.github+json"},
        )
        if not isinstance(data, list):
            return []

        cves = []
        for advisory in data[:MAX_CVE_RESULTS]:
            cvss_score = self._safe_float((advisory.get("cvss") or {}).get("score"))
            cves.append(
                {
                    "id": advisory.get("ghsa_id", ""),
                    "cve_id": advisory.get("cve_id", ""),
                    "description": str(advisory.get("summary", ""))[:250],
                    "cvss_score": cvss_score,
                    "cvss_severity": advisory.get("severity", "Unknown"),
                    "source": "GitHub Advisory",
                }
            )

        return cves

    def _extract_description(self, descriptions: Any) -> str:
        if not isinstance(descriptions, list):
            return ""
        for entry in descriptions:
            value = entry.get("value") if isinstance(entry, dict) else None
            if value:
                return str(value)[:250]
        return ""

    def _extract_nvd_metrics(self, metrics: Dict[str, Any]) -> Tuple[float, str]:
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_score = self._safe_float(cvss_v31.get("baseScore"))
        cvss_severity = cvss_v31.get("baseSeverity", "Unknown")

        if cvss_score > 0:
            return cvss_score, cvss_severity

        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
        cvss_score = self._safe_float(cvss_v2.get("baseScore"))
        return cvss_score, self._get_severity_from_score(cvss_score)

    def _extract_osv_score(self, vulnerability: Dict[str, Any]) -> float:
        for severity in vulnerability.get("severity", []):
            if severity.get("type") == "CVSS_V3":
                score = severity.get("score", "")
                if isinstance(score, str) and "/" in score:
                    score = score.rsplit("/", maxsplit=1)[-1]
                return self._safe_float(score)
        return 0.0

    def _safe_float(self, value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _get_severity_from_score(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score > 0:
            return "Low"
        return "None"

    async def enrich_cve(self, service_name: str, version: str) -> CVEEnrichment:
        """Fetch and aggregate vulnerability information for a service version."""
        if not version or version == UNKNOWN_VERSION:
            return self._empty_cve_result()

        cache_key = f"{service_name}:{version}"
        cached = self.cache.get_cached_cve(cache_key)
        if cached:
            logger.info("Using cached data for %s %s", service_name, version)
            return cached

        logger.info("Fetching CVEs for %s %s", service_name, version)

        cpe_string = self.build_cpe_string(service_name, version)
        circl_cves, nvd_cves, osv_cves = await asyncio.gather(
            self.fetch_from_circl(service_name, version),
            self.fetch_from_nvd(cpe_string),
            self.fetch_from_osv(service_name, version),
        )

        all_cves = [*circl_cves, *nvd_cves, *osv_cves]
        if len(all_cves) < 3:
            all_cves.extend(await self.fetch_github_advisory(service_name))

        unique_cves = self._deduplicate_cves(all_cves)
        highest_cvss = unique_cves[0].get("cvss_score", 0.0) if unique_cves else 0.0
        has_exploit = self._check_known_exploits(service_name, version)

        enriched_data = {
            "cves": unique_cves[:MAX_CVE_RESULTS],
            "total_cves": len(unique_cves),
            "highest_cvss": highest_cvss,
            "highest_severity": self._get_severity_from_score(highest_cvss),
            "has_exploit": has_exploit,
            "has_metasploit": has_exploit,
            "exploit_available": has_exploit,
        }

        self.cache.cache_cve_data(cache_key, enriched_data)
        return enriched_data

    def _deduplicate_cves(self, cves: List[CVERecord]) -> List[CVERecord]:
        unique_cves: Dict[str, CVERecord] = {}
        for cve in cves:
            cve_id = cve.get("id") or cve.get("cve_id")
            if cve_id and cve_id not in unique_cves:
                unique_cves[cve_id] = cve

        deduplicated = list(unique_cves.values())
        deduplicated.sort(key=lambda item: item.get("cvss_score", 0), reverse=True)
        return deduplicated

    def _empty_cve_result(self) -> CVEEnrichment:
        return {
            "cves": [],
            "total_cves": 0,
            "highest_cvss": 0,
            "highest_severity": "None",
            "has_exploit": False,
            "has_metasploit": False,
            "exploit_available": False,
        }

    def _check_known_exploits(self, service: str, version: str) -> bool:
        """Check for known exploits based on service and version."""
        service_lower = service.lower()
        for key, exploits in KNOWN_EXPLOITS.items():
            if key in service_lower:
                for exploit_version, exploit_name in exploits.items():
                    if exploit_version in version:
                        logger.info("Known exploit found: %s", exploit_name)
                        return True

        return False


class PortScanner:
    """Main port scanning implementation."""

    def __init__(self, db: Any = None) -> None:
        self.db = db
        self.cve_cache = CVECache()
        self.cve_fetcher = CVEFetcher(self.cve_cache)

    def _check_nmap_available(self) -> bool:
        """Check if the python-nmap package is installed."""
        try:
            import nmap  # noqa: F401

            return True
        except ImportError:
            return False

    def _build_error_result(self, target: str, error: str) -> ScanSummary:
        return {
            "target": target,
            "error": error,
            "open_ports": [],
            "total_open": 0,
            "risk_level": "Error",
        }

    def _base_scan_result(self, target: str) -> ScanSummary:
        return {
            "target": target,
            "scanned_ports": SCAN_PORTS,
            "open_ports": [],
            "total_open": 0,
            "dangerous_ports": [],
            "risk_score": 0,
            "risk_level": "None",
            "scan_time": datetime.utcnow().isoformat(),
        }

    async def scan_ports(self, target: str) -> ScanSummary:
        """Scan ports using Nmap with service version detection."""
        if not self._check_nmap_available():
            return self._build_error_result(
                target,
                "python-nmap is not installed. Install the package and ensure the nmap binary is available.",
            )

        try:
            import nmap

            nm = nmap.PortScanner()
            port_string = ",".join(str(port) for port in SCAN_PORTS)
            logger.info("Scanning %s ports: %s", target, port_string)
            nm.scan(target, arguments=NMAP_ARGUMENTS_TEMPLATE.format(ports=port_string))

            results = self._base_scan_result(target)
            for port_info in await self._collect_open_ports(nm):
                results["open_ports"].append(port_info)
                if port_info.get("dangerous"):
                    results["dangerous_ports"].append(port_info)

            results["total_open"] = len(results["open_ports"])
            results["risk_score"] = self._calculate_risk_score(results["open_ports"])
            results["risk_level"] = self._get_risk_level(results["risk_score"])
            return results
        except Exception as exc:
            logger.exception("Scan failed for %s", target)
            return self._build_error_result(target, str(exc))
        finally:
            await self.cve_fetcher.close()

    async def _collect_open_ports(self, nm: Any) -> List[PortScanResult]:
        tasks = []

        for host in nm.all_hosts():
            for protocol in nm[host].all_protocols():
                ports_info = nm[host][protocol]

                for port, info in ports_info.items():
                    if info.get("state") != OPEN_STATE:
                        continue

                    tasks.append(self._build_port_info(protocol, port, info))

        if not tasks:
            return []
        return await asyncio.gather(*tasks)

    async def _build_port_info(self, protocol: str, port: int, info: Dict[str, Any]) -> PortScanResult:
        port_info = {
            "port": port,
            "protocol": protocol,
            "service": info.get("name", UNKNOWN_SERVICE),
            "version": info.get("version", ""),
            "product": info.get("product", ""),
            "state": OPEN_STATE,
            "dangerous": port in DANGEROUS_PORTS,
        }

        if port in DANGEROUS_PORTS:
            port_info["dangerous_info"] = DANGEROUS_PORTS[port]

        if port_info["version"] and port_info["product"]:
            service_name = self._resolve_service_name(port_info)
            enriched = await self.cve_fetcher.enrich_cve(service_name, port_info["version"])
            port_info["cve_enrichment"] = enriched

            display_message = self._build_display_message(service_name, port_info["version"], enriched)
            if display_message:
                port_info["display_message"] = display_message

        return port_info

    def _resolve_service_name(self, port_info: PortScanResult) -> str:
        service = port_info.get("service")
        if service and service != UNKNOWN_SERVICE:
            return service
        return port_info.get("product", UNKNOWN_SERVICE)

    def _build_display_message(
        self,
        service_name: str,
        version: str,
        enrichment: CVEEnrichment,
    ) -> Optional[str]:
        if enrichment.get("total_cves", 0) <= 0 or not enrichment.get("cves"):
            return None

        highest = enrichment["cves"][0]
        message = (
            f"{service_name} {version} - {enrichment['total_cves']} CVEs found. "
            f"Highest: {highest['id']} (CVSS {enrichment['highest_cvss']} {enrichment['highest_severity']})"
        )
        if enrichment.get("has_exploit"):
            message += " - Metasploit module available."
        return message

    def _calculate_risk_score(self, open_ports: List[PortScanResult]) -> float:
        score = 0.0
        for port in open_ports:
            if port.get("dangerous"):
                danger = port.get("dangerous_info", {})
                if danger.get("risk") == "Critical":
                    score += 35
                elif danger.get("risk") == "High":
                    score += 20
                else:
                    score += 10

            highest_cvss = port.get("cve_enrichment", {}).get("highest_cvss", 0)
            if highest_cvss >= 9.0:
                score += 40
            elif highest_cvss >= 7.0:
                score += 25
            elif highest_cvss >= 4.0:
                score += 10

        return min(100, score)

    def _get_risk_level(self, score: float) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 30:
            return "Medium"
        if score > 0:
            return "Low"
        return "None"


def scan_ports_sync(target_url: str, fast_mode: bool = False) -> ScanSummary:
    """Synchronous wrapper for callers that are not running an event loop yet."""
    parsed = urlparse(target_url)
    target = parsed.hostname or target_url

    if fast_mode:
        logger.debug("fast_mode is currently unused in scan_ports_sync for target %s", target)

    scanner = PortScanner()
    loop = asyncio.new_event_loop()
    previous_loop: Optional[asyncio.AbstractEventLoop]
    try:
        previous_loop = asyncio.get_event_loop()
    except RuntimeError:
        previous_loop = None

    asyncio.set_event_loop(loop)

    try:
        return loop.run_until_complete(scanner.scan_ports(target))
    except Exception as exc:
        logger.exception("Synchronous scan failed for %s", target)
        return scanner._build_error_result(target, str(exc))
    finally:
        asyncio.set_event_loop(previous_loop)
        loop.close()

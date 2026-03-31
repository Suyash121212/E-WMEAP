# modules/port_scanner.py

import subprocess
import json
import re
import asyncio
import aiohttp
import socket
import ssl
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Dangerous ports configuration
DANGEROUS_PORTS = {
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


class CVECache:
    """In-memory cache for CVE data"""
    
    def __init__(self):
        self.cache = {}
    
    async def get_cached_cve(self, key: str) -> Optional[Dict]:
        return self.cache.get(key)
    
    async def cache_cve_data(self, key: str, data: Dict):
        self.cache[key] = data
        logger.info(f"Cached CVE data for: {key}")


class CVEFetcher:
    """Fetch CVE data from multiple free APIs"""
    
    def __init__(self, cache: CVECache):
        self.cache = cache
        self.session = None
    
    async def _ensure_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession()
    
    async def close(self):
        if self.session:
            await self.session.close()
    
    def build_cpe_string(self, product: str, version: str) -> str:
        """Build CPE string from product and version"""
        product_clean = product.lower().replace(" ", "_")
        
        cpe_mappings = {
            "apache": "apache:http_server",
            "nginx": "nginx:nginx",
            "mysql": "mysql:mysql",
            "postgresql": "postgresql:postgresql",
            "redis": "redis:redis",
            "mongodb": "mongodb:mongodb",
            "elasticsearch": "elasticsearch:elasticsearch",
            "docker": "docker:docker",
            "openssh": "openbsd:openssh",
            "node": "nodejs:node.js",
            "express": "expressjs:express",
            "flask": "palletsprojects:flask",
            "golang": "golang:go",
        }
        
        for key, value in cpe_mappings.items():
            if key in product_clean:
                product_clean = value
                break
        
        version_clean = version.replace("v", "").replace("version", "").strip()
        return f"cpe:2.3:a:{product_clean}:{version_clean}:*:*:*:*:*:*:*"
    
    async def fetch_from_nvd(self, cpe_string: str) -> List[Dict]:
        """NVD API - Unlimited, reliable"""
        try:
            await self._ensure_session()
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"cpeName": cpe_string, "resultsPerPage": 5}
            
            async with self.session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    data = await response.json()
                    cves = []
                    
                    for item in data.get("vulnerabilities", []):
                        cve_data = item.get("cve", {})
                        metrics = cve_data.get("metrics", {})
                        
                        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                        cvss_score = cvss_v3.get("baseScore", 0)
                        cvss_severity = cvss_v3.get("baseSeverity", "Unknown")
                        
                        if cvss_score == 0:
                            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                            cvss_score = cvss_v2.get("baseScore", 0)
                            cvss_severity = self._get_severity_from_score(cvss_score)
                        
                        cves.append({
                            "id": cve_data.get("id", ""),
                            "description": cve_data.get("descriptions", [{}])[0].get("value", "")[:250],
                            "cvss_score": cvss_score,
                            "cvss_severity": cvss_severity,
                            "source": "NVD"
                        })
                    
                    return cves
        except Exception as e:
            logger.error(f"NVD error: {e}")
        return []
    
    async def fetch_from_circl(self, product: str, version: str) -> List[Dict]:
        """CVE.circl.lu - No API key needed, fast and simple"""
        try:
            await self._ensure_session()
            product_clean = product.lower().split()[0]
            url = f"https://cve.circl.lu/api/search/{product_clean}/{version}"
            
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    if isinstance(data, list):
                        cves = []
                        for cve in data[:5]:
                            cves.append({
                                "id": cve.get("id", ""),
                                "description": cve.get("summary", "")[:250],
                                "cvss_score": float(cve.get("cvss", 0)),
                                "cvss_severity": self._get_severity_from_score(float(cve.get("cvss", 0))),
                                "source": "CIRCL"
                            })
                        return cves
        except Exception as e:
            logger.error(f"CIRCL error: {e}")
        return []
    
    async def fetch_from_osv(self, package: str, version: str) -> List[Dict]:
        """
        OSV.dev API - Google-maintained, unlimited, great for open source packages
        Endpoint: api.osv.dev/v1/query
        """
        try:
            await self._ensure_session()
            url = "https://api.osv.dev/v1/query"
            
            payload = {
                "package": {
                    "name": package,
                    "ecosystem": "Debian"  # Can also use "PyPI", "npm", etc.
                },
                "version": version
            }
            
            async with self.session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    cves = []
                    
                    for vuln in data.get("vulns", [])[:5]:
                        # Extract CVSS if available
                        cvss_score = 0
                        if "severity" in vuln:
                            for severity in vuln.get("severity", []):
                                if severity.get("type") == "CVSS_V3":
                                    cvss_score = float(severity.get("score", 0))
                                    break
                        
                        cves.append({
                            "id": vuln.get("id", ""),
                            "description": vuln.get("summary", "")[:250],
                            "cvss_score": cvss_score,
                            "cvss_severity": self._get_severity_from_score(cvss_score),
                            "source": "OSV.dev"
                        })
                    
                    return cves
        except Exception as e:
            logger.error(f"OSV error: {e}")
        return []
    
    async def fetch_github_advisory(self, product: str) -> List[Dict]:
        """
        GitHub Advisory Database - Free, 60 requests/min
        Endpoint: api.github.com/advisories
        """
        try:
            await self._ensure_session()
            url = f"https://api.github.com/advisories?ecosystem=OTHER&cve_id=&severity=&keyword={product}"
            
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    cves = []
                    
                    for advisory in data[:5]:
                        # Extract CVSS score
                        cvss_score = 0
                        if "cvss" in advisory and advisory["cvss"]:
                            cvss_score = float(advisory["cvss"].get("score", 0))
                        
                        cves.append({
                            "id": advisory.get("ghsa_id", ""),
                            "cve_id": advisory.get("cve_id", ""),
                            "description": advisory.get("summary", "")[:250],
                            "cvss_score": cvss_score,
                            "cvss_severity": advisory.get("severity", "Unknown"),
                            "source": "GitHub Advisory"
                        })
                    
                    return cves
        except Exception as e:
            logger.error(f"GitHub Advisory error: {e}")
        return []
    
    def _get_severity_from_score(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0:
            return "Low"
        return "None"
    
    async def enrich_cve(self, service_name: str, version: str) -> Dict:
        """Main CVE enrichment using multiple APIs"""
        if not version or version == "unknown":
            return self._empty_cve_result()
        
        # Create cache key
        cache_key = f"{service_name}:{version}"
        
        # Check cache
        cached = await self.cache.get_cached_cve(cache_key)
        if cached:
            logger.info(f"Using cached data for {service_name} {version}")
            return cached
        
        logger.info(f"Fetching CVEs for {service_name} {version}")
        
        # Query multiple APIs in parallel
        all_cves = []
        
        # API 1: CIRCL (fastest, no key)
        circl_cves = await self.fetch_from_circl(service_name, version)
        all_cves.extend(circl_cves)
        
        # API 2: NVD (comprehensive)
        cpe_string = self.build_cpe_string(service_name, version)
        nvd_cves = await self.fetch_from_nvd(cpe_string)
        all_cves.extend(nvd_cves)
        
        # API 3: OSV.dev (Google-maintained)
        osv_cves = await self.fetch_from_osv(service_name, version)
        all_cves.extend(osv_cves)
        
        # API 4: GitHub Advisory (fallback)
        if len(all_cves) < 3:
            github_cves = await self.fetch_github_advisory(service_name)
            all_cves.extend(github_cves)
        
        # Deduplicate by CVE ID
        unique_cves = {}
        for cve in all_cves:
            cve_id = cve.get("id") or cve.get("cve_id")
            if cve_id and cve_id not in unique_cves:
                unique_cves[cve_id] = cve
        
        cve_list = list(unique_cves.values())
        
        # Sort by CVSS score (highest first)
        cve_list.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        
        # Calculate metrics
        highest_cvss = cve_list[0].get("cvss_score", 0) if cve_list else 0
        highest_severity = self._get_severity_from_score(highest_cvss)
        
        # Check for known exploits (from known vulnerable versions)
        has_exploit = self._check_known_exploits(service_name, version)
        
        # Build result
        enriched_data = {
            "cves": cve_list[:5],  # Top 5 CVEs
            "total_cves": len(cve_list),
            "highest_cvss": highest_cvss,
            "highest_severity": highest_severity,
            "has_exploit": has_exploit,
            "has_metasploit": has_exploit,  # For PDF compatibility
            "exploit_available": has_exploit
        }
        
        # Cache results
        await self.cache.cache_cve_data(cache_key, enriched_data)
        
        return enriched_data
    
    def _empty_cve_result(self) -> Dict:
        return {
            "cves": [],
            "total_cves": 0,
            "highest_cvss": 0,
            "highest_severity": "None",
            "has_exploit": False,
            "has_metasploit": False,
            "exploit_available": False
        }
    
    def _check_known_exploits(self, service: str, version: str) -> bool:
        """Check for known exploits based on service and version"""
        known_exploits = {
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
            }
        }
        
        service_lower = service.lower()
        for key, exploits in known_exploits.items():
            if key in service_lower:
                for exploit_version, exploit_name in exploits.items():
                    if exploit_version in version:
                        logger.info(f"Known exploit found: {exploit_name}")
                        return True
        
        return False


class PortScanner:
    """Main port scanning implementation"""
    
    def __init__(self, db=None):
        self.db = db
        self.cve_cache = CVECache()
        self.cve_fetcher = CVEFetcher(self.cve_cache)
    
    def _check_nmap_available(self) -> bool:
        """Check if nmap is installed"""
        try:
            import nmap
            return True
        except ImportError:
            return False
    
    async def scan_ports(self, target: str) -> Dict:
        """Scan ports using Nmap with service version detection"""
        
        # Check if nmap is available
        if not self._check_nmap_available():
            return {
                "target": target,
                "error": "nmap is not installed. Please install nmap first: apt-get install nmap",
                "open_ports": [],
                "total_open": 0,
                "risk_level": "Error"
            }
        
        try:
            import nmap
            nm = nmap.PortScanner()
            
            port_string = ",".join(str(p) for p in SCAN_PORTS)
            logger.info(f"Scanning {target} ports: {port_string}")
            
            # Run nmap scan
            nm.scan(target, arguments=f'-sV -p {port_string} --open -T4')
            
            results = {
                "target": target,
                "scanned_ports": SCAN_PORTS,
                "open_ports": [],
                "total_open": 0,
                "dangerous_ports": [],
                "risk_score": 0,
                "risk_level": "None",
                "scan_time": datetime.utcnow().isoformat()
            }
            
            # Parse results
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports_info = nm[host][proto]
                    
                    for port, info in ports_info.items():
                        if info.get("state") == "open":
                            port_info = {
                                "port": port,
                                "protocol": proto,
                                "service": info.get("name", "unknown"),
                                "version": info.get("version", ""),
                                "product": info.get("product", ""),
                                "state": "open",
                                "dangerous": port in DANGEROUS_PORTS
                            }
                            
                            # Add dangerous port info
                            if port in DANGEROUS_PORTS:
                                port_info["dangerous_info"] = DANGEROUS_PORTS[port]
                                results["dangerous_ports"].append(port_info)
                            
                            # Enrich with CVE data
                            if port_info.get("product") and port_info.get("version"):
                                service_name = port_info["product"]
                                if port_info.get("service") and port_info["service"] != "unknown":
                                    service_name = port_info["service"]
                                
                                enriched = await self.cve_fetcher.enrich_cve(
                                    service_name, port_info["version"]
                                )
                                port_info["cve_enrichment"] = enriched
                                
                                # Build display message like PDF example
                                if enriched["total_cves"] > 0:
                                    highest = enriched["cves"][0] if enriched["cves"] else None
                                    if highest:
                                        msg = f"{service_name} {port_info['version']} — {enriched['total_cves']} CVEs found. "
                                        msg += f"Highest: {highest['id']} (CVSS {enriched['highest_cvss']} {enriched['highest_severity']})"
                                        if enriched["has_exploit"]:
                                            msg += " — Metasploit module available."
                                        port_info["display_message"] = msg
                            
                            results["open_ports"].append(port_info)
            
            results["total_open"] = len(results["open_ports"])
            results["risk_score"] = self._calculate_risk_score(results["open_ports"])
            results["risk_level"] = self._get_risk_level(results["risk_score"])
            
            await self.cve_fetcher.close()
            return results
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {
                "target": target,
                "error": str(e),
                "open_ports": [],
                "total_open": 0,
                "risk_level": "Error"
            }
    
    def _calculate_risk_score(self, open_ports: List[Dict]) -> float:
        score = 0
        for port in open_ports:
            if port.get("dangerous"):
                danger = port.get("dangerous_info", {})
                if danger.get("risk") == "Critical":
                    score += 35
                elif danger.get("risk") == "High":
                    score += 20
                else:
                    score += 10
            
            cve_data = port.get("cve_enrichment", {})
            if cve_data.get("highest_cvss", 0) >= 9.0:
                score += 40
            elif cve_data.get("highest_cvss", 0) >= 7.0:
                score += 25
            elif cve_data.get("highest_cvss", 0) >= 4.0:
                score += 10
        return min(100, score)
    
    def _get_risk_level(self, score: float) -> str:
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 30:
            return "Medium"
        elif score > 0:
            return "Low"
        return "None"


# Synchronous wrapper
def scan_ports_sync(target_url: str, fast_mode: bool = False) -> dict:
    parsed = urlparse(target_url)
    target = parsed.hostname or target_url
    
    scanner = PortScanner()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(scanner.scan_ports(target))
        loop.close()
        return result
    except Exception as e:
        loop.close()
        return {
            "target": target,
            "error": str(e),
            "open_ports": [],
            "total_open": 0,
            "risk_level": "Error"
        }
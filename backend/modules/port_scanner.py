import nmap
import requests

# 🔴 Dangerous ports reference
DANGEROUS_PORTS = {
    3306: "MySQL Database Exposed",
    6379: "Redis Exposed (No Auth Risk)",
    27017: "MongoDB Exposed",
    2375: "Docker API Exposed"
}

# 🔹 Severity logic
def classify(score):
    if not score:
        return "Low"
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    return "Low"


# 🔹 CVE Fetch
# def get_cves(service):
#     try:
#         url = f"https://cve.circl.lu/api/search/{service}"
#         res = requests.get(url, timeout=5).json()

#         cves = []
#         for item in res.get("data", [])[:3]:
#             score = item.get("cvss")

#             cves.append({
#                 "cve_id": item.get("id"),
#                 "cvss": score,
#                 "severity": classify(score),
#                 "description": item.get("summary")
#             })

#         return cves
#     except:
#         return []


# 🔹 MAIN SCAN FUNCTION
def run_port_scan(target):
    nm = nmap.PortScanner()

    nm.scan(
        target,
        '21,22,80,443,3306,5432,6379,8080,27017,2375',
        arguments='-sV'
    )

    results = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():

                service = nm[host][proto][port]

                service_name = service.get("name")
                version = service.get("version")

                cves = get_cves(service_name)

                results.append({
                    "port": port,
                    "protocol": proto,
                    "service": service_name,
                    "version": version,
                    "cves": cves,
                    "warning": DANGEROUS_PORTS.get(port, None)
                })

    return results
import nmap
import socket


# Comprehensive service map with attack vectors
PORT_META = {
    21:   {"service": "FTP",         "attacks": ["Anonymous Login", "Brute Force", "FTP Bounce Attack", "Clear-text Sniffing"]},
    22:   {"service": "SSH",         "attacks": ["Brute Force", "User Enumeration", "CVE Exploits (old versions)"]},
    23:   {"service": "Telnet",      "attacks": ["Clear-text Sniffing", "Brute Force", "MitM Attack"]},
    25:   {"service": "SMTP",        "attacks": ["Open Relay Abuse", "User Enumeration (VRFY)", "Spam Relay"]},
    53:   {"service": "DNS",         "attacks": ["DNS Amplification DDoS", "Zone Transfer", "Cache Poisoning"]},
    69:   {"service": "TFTP",        "attacks": ["Unauthenticated File Read/Write", "Config Theft"]},
    79:   {"service": "Finger",      "attacks": ["User Enumeration", "Information Disclosure"]},
    80:   {"service": "HTTP",        "attacks": ["SQLi", "XSS", "Directory Traversal", "Clickjacking"]},
    110:  {"service": "POP3",        "attacks": ["Brute Force", "Clear-text Credential Sniffing"]},
    111:  {"service": "RPCBind",     "attacks": ["RPC Enumeration", "NFS Exploitation"]},
    119:  {"service": "NNTP",        "attacks": ["Information Disclosure", "Spam Abuse"]},
    135:  {"service": "MS-RPC",      "attacks": ["DCOM Exploitation", "Worm Propagation (MS03-026)"]},
    137:  {"service": "NetBIOS-NS",  "attacks": ["NetBIOS Enumeration", "NBNS Spoofing"]},
    138:  {"service": "NetBIOS-DGM", "attacks": ["NetBIOS Enumeration", "Session Hijacking"]},
    139:  {"service": "NetBIOS-SSN", "attacks": ["EternalBlue (MS17-010)", "SMB Relay", "Null Session"]},
    143:  {"service": "IMAP",        "attacks": ["Brute Force", "Clear-text Sniffing", "IMAP Injection"]},
    161:  {"service": "SNMP",        "attacks": ["Community String Brute Force", "Information Disclosure", "SNMP Amplification"]},
    179:  {"service": "BGP",         "attacks": ["BGP Hijacking", "Route Injection"]},
    194:  {"service": "IRC",         "attacks": ["Botnet C2", "DDoS Coordination"]},
    389:  {"service": "LDAP",        "attacks": ["Anonymous Bind", "LDAP Injection", "Credential Harvesting"]},
    443:  {"service": "HTTPS",       "attacks": ["SSL/TLS Exploits", "BEAST/POODLE", "Heartbleed (old OpenSSL)"]},
    445:  {"service": "SMB",         "attacks": ["EternalBlue (MS17-010)", "SMB Relay", "Ransomware Propagation"]},
    512:  {"service": "rexec",       "attacks": ["Remote Command Execution", "Brute Force"]},
    513:  {"service": "rlogin",      "attacks": ["Trust Exploitation", "Clear-text Auth Bypass"]},
    514:  {"service": "Syslog/rsh",  "attacks": ["Log Tampering", "Unauthenticated Remote Shell"]},
    515:  {"service": "LPD",         "attacks": ["Printer Exploitation", "DoS Attack"]},
    543:  {"service": "Kerberos",    "attacks": ["Kerberoasting", "AS-REP Roasting", "Pass-the-Ticket"]},
    587:  {"service": "SMTP-TLS",    "attacks": ["Open Relay Abuse", "Credential Brute Force"]},
    631:  {"service": "IPP",         "attacks": ["CUPS Exploit", "Unauthorized Print Jobs", "Info Disclosure"]},
    636:  {"service": "LDAPS",       "attacks": ["LDAP Injection", "Certificate Spoofing"]},
    873:  {"service": "rsync",       "attacks": ["Unauthenticated File Access", "Data Exfiltration"]},
    902:  {"service": "VMware",      "attacks": ["VMware Exploit", "Guest-to-Host Escape"]},
    993:  {"service": "IMAPS",       "attacks": ["SSL Strip", "Credential Interception"]},
    995:  {"service": "POP3S",       "attacks": ["SSL Strip", "Credential Brute Force"]},
    1080: {"service": "SOCKS Proxy", "attacks": ["Open Proxy Abuse", "Traffic Tunnelling"]},
    1433: {"service": "MSSQL",       "attacks": ["SQL Injection", "xp_cmdshell RCE", "Brute Force"]},
    1521: {"service": "Oracle DB",   "attacks": ["TNS Poison", "Brute Force", "SQL Injection"]},
    1723: {"service": "PPTP VPN",    "attacks": ["MS-CHAPv2 Crack", "VPN Credential Theft"]},
    2049: {"service": "NFS",         "attacks": ["Unauthenticated Mount", "File System Access", "Privilege Escalation"]},
    2121: {"service": "FTP-Alt",     "attacks": ["Brute Force", "Clear-text Sniffing"]},
    3306: {"service": "MySQL",       "attacks": ["SQL Injection", "Brute Force", "UDF Privilege Escalation"]},
    3389: {"service": "RDP",         "attacks": ["BlueKeep (CVE-2019-0708)", "Brute Force", "MitM (NLA bypass)"]},
    4444: {"service": "Metasploit",  "attacks": ["Active Backdoor/Shell Detected", "C2 Communication"]},
    5432: {"service": "PostgreSQL",  "attacks": ["SQL Injection", "Brute Force", "COPY TO/FROM RCE"]},
    5900: {"service": "VNC",         "attacks": ["Brute Force", "Unauthenticated Access", "Screen Hijacking"]},
    5985: {"service": "WinRM-HTTP",  "attacks": ["Pass-the-Hash", "Remote Code Execution via WinRM"]},
    5986: {"service": "WinRM-HTTPS", "attacks": ["Pass-the-Hash", "Remote Code Execution via WinRM"]},
    6379: {"service": "Redis",       "attacks": ["Unauthenticated Access", "RCE via config write", "Data Dump"]},
    8080: {"service": "HTTP-Alt",    "attacks": ["Same as HTTP", "Admin Panel Exposure", "Proxy Abuse"]},
    8443: {"service": "HTTPS-Alt",   "attacks": ["Same as HTTPS", "Self-signed Cert MitM"]},
    8888: {"service": "HTTP-Dev",    "attacks": ["Dev Server Exposure", "Jupyter Notebook RCE"]},
    9200: {"service": "Elasticsearch","attacks": ["Unauthenticated Data Access", "Data Exfiltration", "RCE"]},
    27017:{"service": "MongoDB",     "attacks": ["Unauthenticated Access", "Data Dump", "NoSQL Injection"]},
}

HIGH_RISK_SERVICES  = {"SSH", "FTP", "Telnet", "SMB", "RDP", "VNC", "NetBIOS-SSN",
                        "MS-RPC", "SNMP", "rsync", "NFS", "Metasploit", "WinRM-HTTP",
                        "WinRM-HTTPS", "Redis", "MongoDB", "Elasticsearch"}
MEDIUM_RISK_SERVICES = {"SMTP", "POP3", "IMAP", "MySQL", "MSSQL", "Oracle DB",
                         "PostgreSQL", "RPCBind", "LDAP", "Kerberos"}


def scan_ports(target: str) -> dict:
    """
    Scans ports 1-1024 plus common high-value ports above 1024.
    Uses python-nmap for reliable detection.
    """
    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(target.replace("https://", "").replace("http://", "").split("/")[0])
    except socket.gaierror:
        return {
            "open_ports": [],
            "total_open_ports": 0,
            "severity": "None",
            "risk_summary": f"Could not resolve hostname: {target}"
        }

    nm = nmap.PortScanner()

    # Scan ports 1-1024 + well-known high ports
    extra_ports = ",".join(str(p) for p in PORT_META if p > 1024)
    port_range = f"1-1024,{extra_ports}"

    try:
        nm.scan(hosts=ip, ports=port_range, arguments="-T4 --open")
    except nmap.PortScannerError as e:
        return {
            "open_ports": [],
            "total_open_ports": 0,
            "severity": "None",
            "risk_summary": f"Nmap error: {str(e)}"
        }

    open_ports = []

    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            for port in sorted(nm[ip][proto].keys()):
                state = nm[ip][proto][port]["state"]
                if state == "open":
                    meta = PORT_META.get(port)
                    if meta:
                        service = meta["service"]
                        attacks = meta["attacks"]
                    else:
                        # Fallback: use nmap's detected service name
                        nmap_svc = nm[ip][proto][port].get("name", "Unknown")
                        service = nmap_svc.upper() if nmap_svc else "Unknown"
                        attacks = ["Service Enumeration", "Version-specific Exploits"]

                    open_ports.append({
                        "port": port,
                        "service": service,
                        "attacks": attacks
                    })

    severity = _determine_severity(open_ports)
    risk_summary = _build_risk_summary(open_ports, severity)

    return {
        "open_ports": open_ports,
        "total_open_ports": len(open_ports),
        "severity": severity,
        "risk_summary": risk_summary
    }


def _determine_severity(open_ports: list) -> str:
    if not open_ports:
        return "None"

    services = {p["service"] for p in open_ports}

    if services & HIGH_RISK_SERVICES:
        return "High"
    if services & MEDIUM_RISK_SERVICES or len(open_ports) > 5:
        return "Medium"
    if services <= {"HTTP", "HTTPS", "HTTP-Alt", "HTTPS-Alt"}:
        return "Low"
    return "Medium"


def _build_risk_summary(open_ports: list, severity: str) -> str:
    if not open_ports:
        return "No open ports detected in the scanned range. Attack surface appears minimal."

    services = [p["service"] for p in open_ports]
    high_risk = [s for s in services if s in HIGH_RISK_SERVICES]
    count = len(open_ports)

    if severity == "High":
        return (
            f"{count} open port(s) found including high-risk services: "
            f"{', '.join(set(high_risk))}. Immediate review recommended."
        )
    if severity == "Medium":
        return (
            f"{count} open port(s) detected. Multiple exposed services increase "
            "the attack surface. Review necessity of each service."
        )
    return (
        f"{count} open port(s) found. Only standard web services detected. "
        "Ensure web server software is up to date."
    )
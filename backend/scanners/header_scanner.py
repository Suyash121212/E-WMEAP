import requests

def analyze_headers(url):

    try:
        session = requests.Session()
        response = session.get(url, allow_redirects=True, timeout=10)

        headers = response.headers

        findings = []

        # ---------- Content Security Policy ----------

        if "Content-Security-Policy" not in headers:

            findings.append({
                "header": "Content-Security-Policy",
                "value": "Not Present",
                "status": "Missing",
                "severity": "High",
                "impact": "Missing CSP may allow XSS attacks"
            })

        else:

            value = headers["Content-Security-Policy"]

            if "unsafe-inline" in value or "unsafe-eval" in value:

                findings.append({
                    "header": "Content-Security-Policy",
                    "value": value,
                    "status": "Weak Configuration",
                    "severity": "High",
                    "impact": "CSP allows unsafe script execution"
                })

            else:

                findings.append({
                    "header": "Content-Security-Policy",
                    "value": value,
                    "status": "Secure",
                    "severity": "None",
                    "impact": "Strong CSP configuration"
                })

        # ---------- X Frame Options ----------

        if "X-Frame-Options" not in headers:

            findings.append({
                "header": "X-Frame-Options",
                "value": "Not Present",
                "status": "Missing",
                "severity": "Medium",
                "impact": "Website could be vulnerable to clickjacking"
            })

        else:

            value = headers["X-Frame-Options"]

            if "ALLOW" in value.upper():

                findings.append({
                    "header": "X-Frame-Options",
                    "value": value,
                    "status": "Weak Configuration",
                    "severity": "Medium",
                    "impact": "ALLOW-FROM weakens clickjacking protection"
                })

            else:

                findings.append({
                    "header": "X-Frame-Options",
                    "value": value,
                    "status": "Secure",
                    "severity": "None",
                    "impact": "Clickjacking protection enabled"
                })

        # ---------- HSTS ----------

        if "Strict-Transport-Security" not in headers:

            findings.append({
                "header": "Strict-Transport-Security",
                "value": "Not Present",
                "status": "Missing",
                "severity": "High",
                "impact": "Users may be vulnerable to HTTPS downgrade attacks"
            })

        else:

            value = headers["Strict-Transport-Security"]

            if "max-age=0" in value:

                findings.append({
                    "header": "Strict-Transport-Security",
                    "value": value,
                    "status": "Weak Configuration",
                    "severity": "High",
                    "impact": "HSTS disabled or very weak"
                })

            else:

                findings.append({
                    "header": "Strict-Transport-Security",
                    "value": value,
                    "status": "Secure",
                    "severity": "None",
                    "impact": "HSTS properly enforced"
                })

        # ---------- X Content Type Options ----------

        if "X-Content-Type-Options" not in headers:

            findings.append({
                "header": "X-Content-Type-Options",
                "value": "Not Present",
                "status": "Missing",
                "severity": "Medium",
                "impact": "Browser may perform MIME sniffing"
            })

        else:

            value = headers["X-Content-Type-Options"]

            if value.lower() == "nosniff":

                findings.append({
                    "header": "X-Content-Type-Options",
                    "value": value,
                    "status": "Secure",
                    "severity": "None",
                    "impact": "MIME sniffing protection enabled"
                })

            else:

                findings.append({
                    "header": "X-Content-Type-Options",
                    "value": value,
                    "status": "Weak Configuration",
                    "severity": "Medium",
                    "impact": "Incorrect X-Content-Type-Options value"
                })

        # =========================
        # ADDITIONAL HEADER CHECKS
        # =========================

        # ---------- Referrer Policy ----------

        if "Referrer-Policy" not in headers:

            findings.append({
                "header": "Referrer-Policy",
                "value": "Not Present",
                "status": "Missing",
                "severity": "Low",
                "impact": "Referrer information may leak sensitive URLs"
            })

        else:

            findings.append({
                "header": "Referrer-Policy",
                "value": headers["Referrer-Policy"],
                "status": "Present",
                "severity": "None",
                "impact": "Referrer policy configured"
            })

        # ---------- Permissions Policy ----------

        if "Permissions-Policy" not in headers:

            findings.append({
                "header": "Permissions-Policy",
                "value": "Not Present",
                "status": "Missing",
                "severity": "Low",
                "impact": "Browser features like camera/microphone not restricted"
            })

        else:

            findings.append({
                "header": "Permissions-Policy",
                "value": headers["Permissions-Policy"],
                "status": "Present",
                "severity": "None",
                "impact": "Permissions policy configured"
            })

        # ---------- Cross-Origin-Opener-Policy ----------

        if "Cross-Origin-Opener-Policy" not in headers:

            findings.append({
                "header": "Cross-Origin-Opener-Policy",
                "value": "Not Present",
                "status": "Missing",
                "severity": "Medium",
                "impact": "Possible cross-origin window interaction attacks"
            })

        else:

            findings.append({
                "header": "Cross-Origin-Opener-Policy",
                "value": headers["Cross-Origin-Opener-Policy"],
                "status": "Present",
                "severity": "None",
                "impact": "Cross-origin opener policy enabled"
            })

        # ---------- Cross-Origin-Resource-Policy ----------

        if "Cross-Origin-Resource-Policy" not in headers:

            findings.append({
                "header": "Cross-Origin-Resource-Policy",
                "value": "Not Present",
                "status": "Missing",
                "severity": "Medium",
                "impact": "Resources could be accessed from other origins"
            })

        else:

            findings.append({
                "header": "Cross-Origin-Resource-Policy",
                "value": headers["Cross-Origin-Resource-Policy"],
                "status": "Present",
                "severity": "None",
                "impact": "Cross-origin resource policy configured"
            })

        return {
            "total_headers_checked": len(findings),
            "findings": findings
        }

    except Exception as e:
        return {"error": str(e)}
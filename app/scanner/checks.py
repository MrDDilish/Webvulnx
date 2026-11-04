import re
from http.cookies import SimpleCookie

SECURITY_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy", "Medium",
        "Define a restrictive CSP appropriate to the application; begin with Report-Only if needed."),
    "strict-transport-security": ("Missing Strict-Transport-Security", "Low",
        "For HTTPS sites, configure HSTS with an appropriate max-age after confirming HTTPS works."),
    "x-content-type-options": ("Missing X-Content-Type-Options", "Low",
        "Set X-Content-Type-Options: nosniff."),
    "x-frame-options": ("Missing clickjacking protection header", "Low",
        "Use CSP frame-ancestors; optionally set X-Frame-Options for legacy clients."),
    "referrer-policy": ("Missing Referrer-Policy", "Info",
        "Set a policy such as strict-origin-when-cross-origin based on application requirements."),
    "permissions-policy": ("Missing Permissions-Policy", "Info",
        "Restrict browser features the application does not need.")
}

def header_findings(headers, url):
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}
    for key, (title, severity, fix) in SECURITY_HEADERS.items():
        if key not in lower:
            findings.append({"title": title, "severity": severity, "category": "Security Headers",
                             "evidence": f"Response did not include {key}.", "remediation": fix, "url": url})
    server = lower.get("server")
    if server:
        findings.append({"title": "Server banner disclosed", "severity": "Info",
                         "category": "Information Disclosure",
                         "evidence": f"Server response header: {server[:120]}",
                         "remediation": "Consider minimizing version and product details in response headers.",
                         "url": url})
    return findings

def cookie_findings(headers, url):
    findings = []
    raw = headers.get("set-cookie") or headers.get("Set-Cookie")
    if not raw:
        return findings
    # HTTPX may combine multiple Set-Cookie values; inspect each available header value.
    cookies = [x.strip() for x in raw.split(",") if "=" in x]
    for item in cookies:
        name = item.split("=", 1)[0].strip()[:80]
        low = item.lower()
        missing = []
        if "secure" not in low: missing.append("Secure")
        if "httponly" not in low: missing.append("HttpOnly")
        if "samesite" not in low: missing.append("SameSite")
        if missing:
            findings.append({"title": f"Cookie '{name}' missing security attributes",
                "severity": "Low", "category": "Cookie Security",
                "evidence": f"Missing attributes: {', '.join(missing)}.",
                "remediation": "Set Secure on HTTPS cookies, HttpOnly where JavaScript access is unnecessary, and an appropriate SameSite policy.",
                "url": url})
    return findings

def form_findings(html, url):
    # Inventory forms and flag password forms served over plain HTTP; no credentials are submitted.
    findings = []
    if re.search(r'<form\b', html, re.I) and url.lower().startswith("http://"):
        if re.search(r'type\s*=\s*["\']?password', html, re.I):
            findings.append({"title": "Password form served over HTTP", "severity": "High",
                "category": "Transport Security", "evidence": "A password input was found on a page loaded over HTTP.",
                "remediation": "Serve authentication pages exclusively over HTTPS and redirect HTTP to HTTPS.",
                "url": url})
    return findings

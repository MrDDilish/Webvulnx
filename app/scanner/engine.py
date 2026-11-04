import os
import socket
import ssl
from urllib.parse import urlparse, urldefrag
from collections import deque

import httpx
from bs4 import BeautifulSoup

from app.scanner.checks import header_findings, cookie_findings, form_findings
from app.scanner.scope import safe_join

def tls_check(url):
    p = urlparse(url)
    if p.scheme != "https":
        return []
    host, port = p.hostname, p.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        return []
    except ssl.SSLCertVerificationError as exc:
        return [{"title": "TLS certificate validation failed", "severity": "High",
                 "category": "TLS Configuration", "evidence": str(exc)[:250],
                 "remediation": "Install a valid certificate with the correct hostname and complete certificate chain.", "url": url}]
    except Exception as exc:
        return [{"title": "TLS assessment could not be completed", "severity": "Info",
                 "category": "TLS Configuration", "evidence": str(exc)[:200],
                 "remediation": "Manually verify certificate chain, hostname, and expiry.", "url": url}]

def run_scan(target):
    parsed = urlparse(target)
    host = parsed.hostname
    max_pages = min(int(os.getenv("SCAN_MAX_PAGES", "20")), 50)
    timeout = float(os.getenv("SCAN_TIMEOUT_SECONDS", "8"))
    max_requests = min(int(os.getenv("SCAN_MAX_REQUESTS", "40")), 100)
    queue = deque([target])
    visited, findings = set(), []
    request_count = 0
    limits = httpx.Limits(max_connections=3, max_keepalive_connections=2)
    with httpx.Client(timeout=timeout, follow_redirects=True, verify=False,
                      headers={"User-Agent": "WebVulnX/0.1 (authorized security assessment)"},
                      limits=limits) as client:
        while queue and len(visited) < max_pages and request_count < max_requests:
            url = urldefrag(queue.popleft())[0]
            if url in visited:
                continue
            # Only same-host HTTP(S) URLs are crawled.
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                continue
            visited.add(url)
            try:
                response = client.get(url)
                request_count += 1
                # Update host tracking after any redirects
                final_host = urlparse(str(response.url)).hostname
                if response.is_redirect:
                    location = response.headers.get("location", "")
                    findings.append({"title": "Redirect observed", "severity": "Info",
                        "category": "Reconnaissance", "evidence": f"HTTP {response.status_code} redirect to {location[:200]}",
                        "remediation": "Review redirect destinations and ensure external redirects are intentional.", "url": url})
                    continue
                findings.extend(header_findings(response.headers, url))
                findings.extend(cookie_findings(response.headers, url))
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" in content_type:
                    html = response.text[:1_000_000]
                    findings.extend(form_findings(html, url))
                    soup = BeautifulSoup(html, "html.parser")
                    # Use final URL after redirects for crawl scoping
                    final_url = str(response.url)
                    final_host = urlparse(final_url).hostname or host
                    for a in soup.find_all("a", href=True):
                        if len(queue) + len(visited) >= max_pages:
                            break
                        nxt = safe_join(final_url, a["href"], final_host)
                        if nxt and nxt not in visited and nxt not in queue:
                            queue.append(nxt)
            except httpx.HTTPError as exc:
                findings.append({"title": "URL request failed", "severity": "Info",
                    "category": "Reconnaissance", "evidence": str(exc)[:200],
                    "remediation": "Verify target availability and network connectivity.", "url": url})
    findings.extend(tls_check(target))
    # De-duplicate repeated header findings across pages by (title,url).
    unique = {(f["title"], f.get("url")): f for f in findings}
    findings = list(unique.values())
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("Critical", "High", "Medium", "Low", "Info")}
    return {"findings": findings, "summary": {
        "pages_visited": len(visited), "requests_made": request_count,
        "total_findings": len(findings), "severity_counts": counts
    }}

from urllib.parse import urlparse, urljoin
from app.config import allowed_hosts
def in_scope(url: str, original_host: str) -> bool:
    p = urlparse(url)
    return p.scheme in ("http", "https") and p.hostname and p.hostname.lower().rstrip(".") == original_host.lower().rstrip(".")

def safe_join(base: str, href: str, original_host: str):
    candidate = urljoin(base, href)
    return candidate if in_scope(candidate, original_host) else None

import os

# Default practice/lab targets — all are intentionally vulnerable demo sites
# provided by security vendors explicitly for scanner testing.
_DEFAULT_HOSTS = ",".join([
    "localhost",
    "127.0.0.1",
    "testphp.vulnweb.com",
    "testfire.net",
    "demo.testfire.net",
    "www.webscantest.com",
    "zero.webappsecurity.com",
])

allowed_hosts = {
    host.strip().lower()
    for host in os.getenv("SCAN_ALLOWED_HOSTS", _DEFAULT_HOSTS).split(",")
    if host.strip()
}

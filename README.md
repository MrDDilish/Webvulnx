# WebVulnX

A local-first, authorized web application security assessment framework built with Python, FastAPI, HTTPX, BeautifulSoup, SQLite, and a browser dashboard.

## Current MVP checks
- Same-host, bounded crawling
- HTTP security headers
- Server banner disclosure
- Cookie security attributes
- Password input detected on plain HTTP
- TLS certificate validation
- Scan history and findings dashboard

This is a learning prototype, not a replacement for a professional DAST tool or a full penetration test.

## Safety / scope
The backend only accepts hostnames listed in `SCAN_ALLOWED_HOSTS`. Add only systems you own or are explicitly authorized to test. Keep the application bound to localhost. Do not expose this prototype to the public internet. The crawler is limited by page and request caps and does not automatically follow redirects.

## Windows PowerShell installation

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set environment variables in the same PowerShell session:

```powershell
$env:SCAN_ALLOWED_HOSTS="localhost,127.0.0.1"
$env:SCAN_MAX_PAGES="20"
$env:SCAN_MAX_REQUESTS="40"
```

Run:

```powershell
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

## Kali Linux installation

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SCAN_ALLOWED_HOSTS="localhost,127.0.0.1"
uvicorn app.main:app --reload
```

## Test the application

Health check:

```bash
curl http://127.0.0.1:8000/api/health
```

Run automated tests:

```bash
pytest -q
```

## Safe lab target

Run a local intentionally vulnerable target such as OWASP Juice Shop or DVWA in a lab. If Juice Shop is published on `127.0.0.1:3000`, use:
- `SCAN_ALLOWED_HOSTS=localhost,127.0.0.1`
- Target URL: `http://127.0.0.1:3000`

Only scan your own local instance. Do not use public targets without written authorization.

## API endpoints
- `GET /api/health`
- `POST /api/scans` body: `{"target":"http://127.0.0.1:3000"}`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/findings`
- `GET /docs` interactive API documentation

## Next development milestones
1. Add authenticated users and per-user scan ownership.
2. Add robust DNS/IP pinning and redirect re-validation before any production use.
3. Add structured URL/form inventory.
4. Add opt-in safe active tests against dedicated lab fixtures.
5. Add CVSS scoring with transparent rationale.
6. Add PDF/JSON export and evidence screenshots.
7. Add worker queue, cancellation, audit logs, and concurrency controls.

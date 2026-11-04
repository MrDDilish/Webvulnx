import os
import sqlite3
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from app.config import allowed_hosts
from fastapi import FastAPI, Request

from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl

from app.scanner.engine import run_scan

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "webvulnx.db"
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))
app = FastAPI(title="WebVulnX", version="0.1.0", description="Authorized web application security assessment framework")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, target TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, summary TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            title TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL,
            evidence TEXT, remediation TEXT, url TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )""")


init_db()


class ScanRequest(BaseModel):
    target: HttpUrl


def validate_target(target: str):
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, "Only valid HTTP/HTTPS URLs are accepted.")
    if parsed.username or parsed.password:
        raise HTTPException(400, "URLs containing credentials are not allowed.")
    host = parsed.hostname.lower().rstrip(".")
    if host not in allowed_hosts:
        raise HTTPException(403, f"Target host '{host}' is not in SCAN_ALLOWED_HOSTS.")
    return target.rstrip("/")


def perform_scan(scan_id: str, target: str):
    try:
        result = run_scan(target)
        with db() as conn:
            for f in result["findings"]:
                conn.execute("""INSERT INTO findings
                    (scan_id,title,severity,category,evidence,remediation,url)
                    VALUES (?,?,?,?,?,?,?)""",
                    (scan_id, f["title"], f["severity"], f["category"],
                     f["evidence"], f["remediation"], f.get("url", target)))
            conn.execute("UPDATE scans SET status=?, summary=? WHERE id=?",
                         ("completed", json.dumps(result["summary"]), scan_id))
    except Exception as exc:
        with db() as conn:
            conn.execute("UPDATE scans SET status=?, summary=? WHERE id=?",
                         ("failed", json.dumps({"error": str(exc)[:300]}), scan_id))


@app.get("/", response_class=HTMLResponse)
@app.get("/")
def dashboard(request: Request):
    with db() as conn:
        scans = conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 20").fetchall()
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        ).fetchall():
            if row["severity"] in counts:
                counts[row["severity"]] = row["cnt"]
        total = sum(counts.values())

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "WebVulnX Dashboard",
            "counts": counts,
            "total": total,
            "scans": [dict(s) for s in scans],
        }
    )


@app.post("/api/scans")
def create_scan(payload: ScanRequest, background_tasks: BackgroundTasks):
    target = validate_target(str(payload.target))
    scan_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute("INSERT INTO scans(id,target,status,created_at) VALUES(?,?,?,?)",
                     (scan_id, target, "queued", now))
    background_tasks.add_task(perform_scan, scan_id, target)
    return {"scan_id": scan_id, "status": "queued", "target": target}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    return dict(row)


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str):
    with db() as conn:
        exists = conn.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not exists:
            raise HTTPException(404, "Scan not found")
        rows = conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
                            "WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 "
                            "WHEN 'Low' THEN 4 ELSE 5 END", (scan_id,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "WebVulnX"}

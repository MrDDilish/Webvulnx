from app.main import validate_target
from fastapi import HTTPException
import pytest

def test_localhost_allowed(monkeypatch):
    monkeypatch.setenv("SCAN_ALLOWED_HOSTS", "localhost,127.0.0.1")
    assert validate_target("http://localhost:3000") == "http://localhost:3000"

def test_external_host_rejected(monkeypatch):
    monkeypatch.setenv("SCAN_ALLOWED_HOSTS", "localhost")
    with pytest.raises(HTTPException) as err:
        validate_target("https://example.org")
    assert err.value.status_code == 403

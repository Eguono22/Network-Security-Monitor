"""Legacy unit fixtures explicitly use local development mode; auth tests opt in."""
import pytest


@pytest.fixture(autouse=True)
def local_test_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("NSM_AUTH_MODE", "disabled")
    monkeypatch.setenv("NSM_TRUST_ROLE_HEADER", "true")
    monkeypatch.setenv("NSM_API_DEFAULT_ROLE", "admin")
    monkeypatch.setenv("NSM_STORAGE_BACKEND", "file")
    monkeypatch.setenv("NSM_AUTH_STATE_FILE", str(tmp_path / "auth.db"))
    from api.index import app
    monkeypatch.setitem(app.config, "TESTING", True)

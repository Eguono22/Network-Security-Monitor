"""Release security behavior uses real signed sessions and password hashes."""
import json
import re

import pytest
from werkzeug.security import generate_password_hash


@pytest.fixture
def secure_client(monkeypatch, tmp_path):
    from api.index import app
    monkeypatch.setenv("NSM_AUTH_MODE", "password")
    monkeypatch.setenv("NSM_COOKIE_SECURE", "false")
    accounts = {
        name: {"role": role, "password_hash": generate_password_hash("long-test-password")}
        for name, role in [("reader", "viewer"), ("operator", "analyst"), ("owner", "admin")]
    }
    path = tmp_path / "users.json"
    path.write_text(json.dumps(accounts))
    monkeypatch.setenv("NSM_USERS_FILE", str(path))
    monkeypatch.setitem(app.config, "SECRET_KEY", "test-signing-key-with-at-least-32-characters")
    monkeypatch.setitem(app.config, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setenv("NSM_INCIDENTS_LOG_FILE", str(tmp_path / "incidents.db"))
    return app.test_client(), path


def login(client, username="operator", password="long-test-password"):
    page = client.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page)[1]
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token})


def test_protected_routes_and_header_spoofing(secure_client):
    client, _ = secure_client
    for route in ("/", "/dashboard", "/network-watcher", "/devices", "/soc-management", "/threat-intel"):
        assert client.get(route).status_code == 302
    for route in ("/api/alerts", "/api/incidents", "/api/devices", "/api/threat-intel?indicator=1.1.1.1"):
        assert client.get(route, headers={"X-NSM-Role": "admin"}).status_code == 401
    assert login(client, "reader").status_code == 303
    with client.session_transaction() as state:
        token = state["csrf"]
    response = client.patch("/api/incidents/nonexistent", json={"status": "resolved"}, headers={"X-NSM-Role": "admin", "X-CSRF-Token": token})
    assert response.status_code == 403
    assert client.get("/api/incidents/export.csv", headers={"X-NSM-Role": "admin"}).status_code == 403


def test_csrf_login_logout_and_writes(secure_client):
    client, _ = secure_client
    assert client.post("/login", data={"username": "operator", "password": "long-test-password"}).status_code == 400
    assert login(client).status_code == 303
    assert client.patch("/api/incidents/missing", json={"status": "resolved"}).status_code == 400
    assert client.post("/logout").status_code == 400
    with client.session_transaction() as state:
        token = state["csrf"]
    assert client.post("/logout", data={"csrf_token": token}).status_code == 303
    assert client.get("/api/alerts").status_code == 401


def test_role_or_password_change_revokes_session(secure_client):
    client, path = secure_client
    assert login(client).status_code == 303
    accounts = json.loads(path.read_text())
    accounts["operator"]["role"] = "viewer"
    path.write_text(json.dumps(accounts))
    assert client.get("/api/alerts").status_code == 401


def test_authentication_fails_closed_without_configuration(monkeypatch):
    from api.index import app
    monkeypatch.setenv("NSM_AUTH_MODE", "password")
    monkeypatch.setitem(app.config, "SECRET_KEY", None)
    client = app.test_client()
    assert client.get("/api/alerts").status_code == 503
    assert client.get("/ready").status_code == 503
    assert client.get("/health").status_code == 200


def test_secure_cookie_attributes_and_security_headers(secure_client, monkeypatch):
    from api.index import app
    client, _ = secure_client
    monkeypatch.setitem(app.config, "SESSION_COOKIE_SECURE", True)
    response = client.get("/login")
    cookie = response.headers["Set-Cookie"]
    for value in ("Secure", "HttpOnly", "SameSite=Lax"):
        assert value in cookie
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_local_auth_bypass_is_not_allowed_in_production(secure_client, monkeypatch):
    from api.index import app
    client, _ = secure_client
    monkeypatch.setitem(app.config, "TESTING", False)
    monkeypatch.setenv("NSM_AUTH_MODE", "disabled")
    monkeypatch.setenv("NSM_ENV", "production")
    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/alerts", environ_base={"REMOTE_ADDR": "203.0.113.1"}).status_code == 401


def test_login_attempts_are_persistently_throttled(secure_client):
    client, _ = secure_client
    for _ in range(20):
        assert login(client, password="incorrect-password").status_code == 401
    assert login(client).status_code == 429

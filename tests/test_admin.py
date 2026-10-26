"""Offline provisioning must keep hashes private and require deliberate rotation."""
import json
import stat

import pytest
from werkzeug.security import check_password_hash
from network_security_monitor.admin import create_user


def test_provision_and_rotate_account(tmp_path):
    path = tmp_path / "private" / "users.json"
    create_user(path, "emmanuel", "admin", "first-long-password")
    account = json.loads(path.read_text())["emmanuel"]
    assert check_password_hash(account["password_hash"], "first-long-password")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(ValueError, match="Account exists"):
        create_user(path, "emmanuel", "viewer", "replacement-password")
    create_user(path, "emmanuel", "viewer", "replacement-password", replace=True)
    account = json.loads(path.read_text())["emmanuel"]
    assert account["role"] == "viewer"
    assert check_password_hash(account["password_hash"], "replacement-password")


def test_provision_rejects_weak_password_and_invalid_username(tmp_path):
    path = tmp_path / "users.json"
    with pytest.raises(ValueError, match="12 characters"):
        create_user(path, "admin", "admin", "short")
    with pytest.raises(ValueError, match="username"):
        create_user(path, "<script>", "admin", "a-long-test-password")
    assert not path.exists()

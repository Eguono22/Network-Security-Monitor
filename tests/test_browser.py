"""Desktop/mobile acceptance flow against real HTTP, auth, and PostgreSQL."""
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

import pytest
from werkzeug.security import generate_password_hash
from tests.test_postgres import postgres_runtime  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv("NSM_RUN_BROWSER_TESTS") != "1", reason="Opt in with NSM_RUN_BROWSER_TESTS=1")


def test_analyst_workflow_desktop_and_mobile(postgres_runtime, tmp_path):
    from playwright.sync_api import sync_playwright, expect
    from network_security_monitor.incident_manager import IncidentManager
    from network_security_monitor.storage import event_store
    from tests.test_postgres import alert

    # Actual CLI simulation feeds the same database used by the web process.
    environment = dict(os.environ)
    environment.update(NSM_AUTH_MODE="password", NSM_SECRET_KEY="browser-test-signing-key-of-at-least-32-characters", NSM_COOKIE_SECURE="false", NSM_ENV="development")
    for key in ("NSM_ALERT_WEBHOOK_URL", "NSM_SLACK_WEBHOOK_URL", "NSM_SMTP_HOST", "NSM_ALERT_EMAIL_TO"):
        environment[key] = ""
    simulation = subprocess.run([sys.executable, "-m", "network_security_monitor", "--simulate", "--no-dashboard"], env=environment, capture_output=True, text=True, timeout=90)
    assert simulation.returncode == 0, simulation.stderr
    case = IncidentManager().create_case(alert())
    event_store("", "alerts").append_alert(alert())
    users = tmp_path / "users.json"
    users.write_text(json.dumps({
        "analyst": {"role": "analyst", "password_hash": generate_password_hash("browser-test-password")},
        "viewer": {"role": "viewer", "password_hash": generate_password_hash("browser-test-password")},
    }))
    environment["NSM_USERS_FILE"] = str(users)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    address = f"http://127.0.0.1:{port}"
    log = (tmp_path / "server.log").open("w")
    server = subprocess.Popen([sys.executable, "-m", "flask", "--app", "api.index", "run", "--port", str(port)], env=environment, stdout=log, stderr=log)
    try:
        for _ in range(100):
            try:
                if urlopen(address + "/health", timeout=1).status == 200:
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("Browser test server did not start")
        with sync_playwright() as playwright:
            launch = {"headless": True}
            if os.getenv("NSM_BROWSER_EXECUTABLE"):
                launch["executable_path"] = os.environ["NSM_BROWSER_EXECUTABLE"]
            browser = playwright.chromium.launch(**launch)
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(address + "/dashboard")
            expect(page).to_have_url(re.compile(r"/login$"))
            page.get_by_label("Username").fill("analyst")
            page.get_by_label("Password").fill("browser-test-password")
            page.get_by_role("button", name="Sign in").click()
            expect(page.get_by_role("heading", name="Your security workspace")).to_be_visible()
            page.goto(address + "/dashboard")
            page.get_by_label("Search alerts").fill("10.0.0.99")
            page.get_by_role("button", name="Inspect Port Scan from 10.0.0.99").first.click()
            expect(page.get_by_role("dialog")).to_be_visible()
            page.get_by_role("button", name="Close alert details").click()
            page.goto(address + "/devices/10.0.0.99")
            form = page.locator("#device-review")
            form.get_by_label("Review status").select_option("investigating")
            form.get_by_label("Owner", exact=True).fill("network-team")
            form.get_by_label("Review notes").fill("Browser acceptance review")
            form.get_by_role("button", name="Save review").click()
            expect(page.locator("#review-feedback")).to_have_text("Review saved.")
            page.reload()
            expect(form.get_by_label("Owner", exact=True)).to_have_value("network-team")
            page.goto(address + "/soc-management?incident_id=" + case["incident_id"])
            update = page.locator("form.update-form")
            update.get_by_label("Assignee", exact=True).fill("acceptance-analyst")
            update.locator("select[name=status]").select_option("assigned")
            update.get_by_role("button", name="Save Incident Update").click()
            expect(page.locator("form.update-form").get_by_label("Assignee", exact=True)).to_have_value("acceptance-analyst")
            for status in ("contained", "resolved"):
                page.locator("form.update-form").locator("select[name=status]").select_option(status)
                page.get_by_role("button", name="Save Incident Update").click()
                expect(page.locator("form.update-form").locator("select[name=status]")).to_have_value(status)
            assert IncidentManager().get_case(case["incident_id"])["status"] == "resolved"
            screenshots = Path(".tmp/release-evidence")
            screenshots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(screenshots / "soc-desktop.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            for route in ("/", "/dashboard", "/devices", "/network-watcher", "/soc-management", "/threat-intel?indicator=10.0.0.99"):
                page.goto(address + route)
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), route
                expect(page.locator("h1")).to_be_visible()
            page.screenshot(path=str(screenshots / "intel-mobile.png"), full_page=True)
            page.get_by_role("button", name="Sign out").click()
            expect(page).to_have_url(re.compile(r"/login$"))
            page.get_by_label("Username").fill("viewer")
            page.get_by_label("Password").fill("browser-test-password")
            page.get_by_role("button", name="Sign in").click()
            page.goto(address + "/soc-management?incident_id=" + case["incident_id"])
            expect(page.locator("form.update-form")).to_have_count(0)
            assert errors == []
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
        log.close()

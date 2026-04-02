import pytest
from app import create_app
from app.extensions import db as _db
from app.core.monitor import NetworkMonitor


@pytest.fixture(autouse=True)
def reset_monitor():
    """Reset the NetworkMonitor singleton state between tests."""
    mon = NetworkMonitor()
    if mon.is_running():
        mon.stop()
    yield
    if mon.is_running():
        mon.stop()


@pytest.fixture
def app():
    application = create_app('testing')
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_get_status(client):
    response = client.get('/api/v1/status')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert 'data' in data


def test_start_monitor(client):
    response = client.post('/api/v1/monitor/start', json={})
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True


def test_stop_monitor(client, app):
    from app.core.monitor import monitor
    with app.app_context():
        if not monitor.is_running():
            monitor.start(app=app)
    response = client.post('/api/v1/monitor/stop')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True


def test_get_alerts(client):
    response = client.get('/api/v1/alerts')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert isinstance(data['data'], list)


def test_get_alerts_summary(client):
    response = client.get('/api/v1/alerts/summary')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert 'total' in data['data']


def test_acknowledge_alert(client, app):
    from app.core.alert_manager import AlertManager
    with app.app_context():
        mgr = AlertManager()
        alert = mgr.create_alert('TEST', 'LOW', '1.1.1.1', '2.2.2.2', 'test alert')
        alert_id = alert.id
    response = client.post(f'/api/v1/alerts/{alert_id}/acknowledge')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert data['data']['acknowledged'] is True


def test_get_stats(client):
    response = client.get('/api/v1/stats')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True


def test_get_threats_summary(client):
    response = client.get('/api/v1/threats/summary')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True

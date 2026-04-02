import pytest
from app import create_app
from app.extensions import db as _db
from app.core.alert_manager import AlertManager


@pytest.fixture
def app():
    application = create_app('testing')
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def manager(app):
    return AlertManager()


def test_create_alert(app, manager):
    with app.app_context():
        alert = manager.create_alert(
            alert_type='PORT_SCAN',
            severity='HIGH',
            src_ip='1.2.3.4',
            dst_ip='5.6.7.8',
            description='Test port scan',
        )
        assert alert.id is not None
        assert alert.alert_type == 'PORT_SCAN'
        assert alert.severity == 'HIGH'
        assert alert.acknowledged is False


def test_get_alerts(app, manager):
    with app.app_context():
        manager.create_alert('TEST', 'LOW', '1.1.1.1', '2.2.2.2', 'test 1')
        manager.create_alert('TEST', 'HIGH', '3.3.3.3', '4.4.4.4', 'test 2')
        alerts = manager.get_alerts()
        assert len(alerts) >= 2


def test_acknowledge_alert(app, manager):
    with app.app_context():
        alert = manager.create_alert('TEST', 'LOW', '1.1.1.1', '2.2.2.2', 'test')
        alert_id = alert.id
        updated = manager.acknowledge_alert(alert_id)
        assert updated is not None
        assert updated.acknowledged is True


def test_delete_alert(app, manager):
    with app.app_context():
        alert = manager.create_alert('TEST', 'LOW', '1.1.1.1', '2.2.2.2', 'to delete')
        alert_id = alert.id
        result = manager.delete_alert(alert_id)
        assert result is True
        result2 = manager.delete_alert(alert_id)
        assert result2 is False


def test_get_summary(app, manager):
    with app.app_context():
        manager.create_alert('TEST', 'LOW', '1.1.1.1', '2.2.2.2', 'low')
        manager.create_alert('TEST', 'HIGH', '1.1.1.1', '2.2.2.2', 'high')
        manager.create_alert('TEST', 'CRITICAL', '1.1.1.1', '2.2.2.2', 'crit')
        summary = manager.get_summary()
        assert summary['LOW'] >= 1
        assert summary['HIGH'] >= 1
        assert summary['CRITICAL'] >= 1
        assert summary['total'] >= 3


def test_get_alerts_by_severity(app, manager):
    with app.app_context():
        manager.create_alert('TEST', 'MEDIUM', '1.1.1.1', '2.2.2.2', 'med')
        alerts = manager.get_alerts(severity='MEDIUM')
        assert all(a.severity == 'MEDIUM' for a in alerts)


def test_get_alerts_unacknowledged(app, manager):
    with app.app_context():
        manager.create_alert('TEST', 'LOW', '1.1.1.1', '2.2.2.2', 'unack')
        alerts = manager.get_alerts(acknowledged=False)
        assert all(a.acknowledged is False for a in alerts)

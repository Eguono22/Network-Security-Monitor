from flask import Blueprint, jsonify, request
from app.core.alert_manager import AlertManager
from app.core.models import Alert
from app.extensions import db

alerts_bp = Blueprint('alerts', __name__)
_manager = AlertManager()


# IMPORTANT: summary route BEFORE parameterized route
@alerts_bp.route('/alerts/summary', methods=['GET'])
def get_alerts_summary():
    summary = _manager.get_summary()
    return jsonify({'success': True, 'data': summary})


@alerts_bp.route('/alerts', methods=['GET'])
def get_alerts():
    severity = request.args.get('severity')
    acknowledged = request.args.get('acknowledged')
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    if acknowledged is not None:
        acknowledged = acknowledged.lower() == 'true'
    alerts = _manager.get_alerts(limit=limit + offset, severity=severity, acknowledged=acknowledged)
    alerts = alerts[offset:offset + limit]
    return jsonify({'success': True, 'data': [a.to_dict() for a in alerts]})


@alerts_bp.route('/alerts/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({'success': False, 'error': 'Alert not found'}), 404
    return jsonify({'success': True, 'data': alert.to_dict()})


@alerts_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    alert = _manager.acknowledge_alert(alert_id)
    if not alert:
        return jsonify({'success': False, 'error': 'Alert not found'}), 404
    return jsonify({'success': True, 'data': alert.to_dict()})


@alerts_bp.route('/alerts/<int:alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    success = _manager.delete_alert(alert_id)
    if not success:
        return jsonify({'success': False, 'error': 'Alert not found'}), 404
    return jsonify({'success': True, 'data': {'deleted': alert_id}})


@alerts_bp.route('/alerts', methods=['DELETE'])
def clear_alerts():
    count = Alert.query.delete()
    db.session.commit()
    return jsonify({'success': True, 'data': {'deleted': count}})

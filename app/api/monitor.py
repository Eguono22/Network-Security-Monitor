from flask import Blueprint, jsonify, request, current_app
from app.core.monitor import monitor

monitor_bp = Blueprint('monitor', __name__)


@monitor_bp.route('/status', methods=['GET'])
def get_status():
    return jsonify({'success': True, 'data': monitor.get_status()})


@monitor_bp.route('/monitor/start', methods=['POST'])
def start_monitor():
    data = request.get_json(silent=True) or {}
    interface = data.get('interface')
    if monitor.is_running():
        return jsonify({'success': False, 'error': 'Monitor is already running'}), 400
    monitor.start(interface=interface, app=current_app._get_current_object())
    return jsonify({'success': True, 'data': monitor.get_status()})


@monitor_bp.route('/monitor/stop', methods=['POST'])
def stop_monitor():
    if not monitor.is_running():
        return jsonify({'success': False, 'error': 'Monitor is not running'}), 400
    monitor.stop()
    return jsonify({'success': True, 'data': monitor.get_status()})


@monitor_bp.route('/connections', methods=['GET'])
def get_connections():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    connections = monitor.get_connections()
    start = (page - 1) * per_page
    end = start + per_page
    paged = connections[start:end]
    return jsonify({
        'success': True,
        'data': paged,
        'total': len(connections),
        'page': page,
        'per_page': per_page,
    })

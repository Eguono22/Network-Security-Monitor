from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request
from app.core.monitor import monitor
from app.core.models import TrafficStat

stats_bp = Blueprint('stats', __name__)


@stats_bp.route('/stats', methods=['GET'])
def get_stats():
    stats = monitor._analyzer.get_stats()
    return jsonify({'success': True, 'data': stats})


@stats_bp.route('/stats/history', methods=['GET'])
def get_stats_history():
    minutes = request.args.get('minutes', 60, type=int)
    since = datetime.utcnow() - timedelta(minutes=minutes)
    rows = (
        TrafficStat.query
        .filter(TrafficStat.created_at >= since)
        .order_by(TrafficStat.created_at.asc())
        .all()
    )
    return jsonify({'success': True, 'data': [r.to_dict() for r in rows]})


@stats_bp.route('/stats/protocols', methods=['GET'])
def get_protocol_stats():
    stats = monitor._analyzer.get_stats()
    return jsonify({'success': True, 'data': stats.get('protocol_counts', {})})

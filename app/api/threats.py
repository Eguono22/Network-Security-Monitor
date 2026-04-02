from collections import defaultdict
from flask import Blueprint, jsonify
from app.core.models import Alert

threats_bp = Blueprint('threats', __name__)


@threats_bp.route('/threats', methods=['GET'])
def get_threats():
    alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    grouped = defaultdict(list)
    for a in alerts:
        grouped[a.alert_type].append(a.to_dict())
    return jsonify({'success': True, 'data': dict(grouped)})


@threats_bp.route('/threats/summary', methods=['GET'])
def get_threats_summary():
    alerts = Alert.query.all()
    counts = defaultdict(int)
    for a in alerts:
        counts[a.alert_type] += 1
    return jsonify({'success': True, 'data': dict(counts)})


@threats_bp.route('/threats/top-sources', methods=['GET'])
def get_top_sources():
    alerts = Alert.query.all()
    ip_counts = defaultdict(int)
    for a in alerts:
        if a.source_ip:
            ip_counts[a.source_ip] += 1
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify({
        'success': True,
        'data': [{'ip': ip, 'count': cnt} for ip, cnt in sorted_ips],
    })

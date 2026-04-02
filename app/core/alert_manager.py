from datetime import datetime
from app.extensions import db, socketio
from app.core.models import Alert


class AlertManager:
    def create_alert(self, alert_type, severity, src_ip, dst_ip, description):
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            source_ip=src_ip,
            destination_ip=dst_ip,
            description=description,
            acknowledged=False,
            timestamp=datetime.utcnow(),
            created_at=datetime.utcnow(),
        )
        db.session.add(alert)
        db.session.commit()
        try:
            socketio.emit('new_alert', alert.to_dict())
        except Exception:
            pass
        return alert

    def get_alerts(self, limit=100, offset=0, severity=None, acknowledged=None):
        query = Alert.query
        if severity:
            query = query.filter(Alert.severity == severity.upper())
        if acknowledged is not None:
            query = query.filter(Alert.acknowledged == acknowledged)
        query = query.order_by(Alert.created_at.desc())
        if offset:
            query = query.offset(offset)
        query = query.limit(limit)
        return query.all()

    def acknowledge_alert(self, alert_id):
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return None
        alert.acknowledged = True
        db.session.commit()
        return alert

    def delete_alert(self, alert_id):
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return False
        db.session.delete(alert)
        db.session.commit()
        return True

    def get_summary(self):
        from sqlalchemy import func
        rows = (
            db.session.query(Alert.severity, func.count(Alert.id))
            .group_by(Alert.severity)
            .all()
        )
        summary = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0, 'total': 0}
        for severity, count in rows:
            if severity in summary:
                summary[severity] = count
            summary['total'] += count
        return summary

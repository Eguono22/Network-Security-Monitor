from datetime import datetime, timezone
from app.extensions import db


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=_utcnow, nullable=False)
    alert_type = db.Column(db.String(64), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    source_ip = db.Column(db.String(45), nullable=True)
    destination_ip = db.Column(db.String(45), nullable=True)
    description = db.Column(db.Text, nullable=True)
    acknowledged = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'description': self.description,
            'acknowledged': self.acknowledged,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class TrafficStat(db.Model):
    __tablename__ = 'traffic_stats'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=_utcnow, nullable=False)
    packets_per_second = db.Column(db.Float, default=0.0)
    bytes_per_second = db.Column(db.Float, default=0.0)
    total_packets = db.Column(db.Integer, default=0)
    total_bytes = db.Column(db.Integer, default=0)
    unique_ips = db.Column(db.Integer, default=0)
    protocol_counts = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'unique_ips': self.unique_ips,
            'protocol_counts': self.protocol_counts or {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class Connection(db.Model):
    __tablename__ = 'connections'

    id = db.Column(db.Integer, primary_key=True)
    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(16), nullable=True)
    state = db.Column(db.String(32), nullable=True)
    bytes_sent = db.Column(db.Integer, default=0)
    bytes_recv = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime, default=_utcnow)
    last_seen = db.Column(db.DateTime, default=_utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'state': self.state,
            'bytes_sent': self.bytes_sent,
            'bytes_recv': self.bytes_recv,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }

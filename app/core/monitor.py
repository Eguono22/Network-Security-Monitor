import time
import threading
from datetime import datetime, timezone
from app.extensions import socketio, db
from app.core.packet_analyzer import PacketAnalyzer
from app.core.threat_detector import ThreatDetector
from app.core.alert_manager import AlertManager
from app.core.models import TrafficStat


class NetworkMonitor:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._running = False
        self._start_time = None
        self._interface = None
        self._thread = None
        self._app = None
        self._analyzer = PacketAnalyzer()
        self._detector = ThreatDetector()
        self._alert_manager = AlertManager()
        self._connections = {}

    def start(self, interface=None, app=None):
        if self._running:
            return
        self._running = True
        self._start_time = datetime.now(timezone.utc).replace(tzinfo=None)
        self._interface = interface
        self._app = app
        self._analyzer.start_capture(interface=interface)
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self._running = False
        self._analyzer.stop_capture()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self._start_time = None

    def is_running(self):
        return self._running

    def get_status(self):
        uptime = None
        if self._start_time:
            delta = datetime.now(timezone.utc).replace(tzinfo=None) - self._start_time
            uptime = int(delta.total_seconds())
        return {
            'is_running': self._running,
            'interface': self._interface,
            'uptime': uptime,
            'start_time': self._start_time.isoformat() if self._start_time else None,
        }

    def get_connections(self):
        return list(self._connections.values())

    def _monitor_loop(self):
        while self._running:
            try:
                stats = self._analyzer.get_stats()
                packets = self._analyzer.get_recent_packets(n=50)
                for pkt in packets:
                    threats = self._detector.analyze_packet(pkt)
                    for threat in threats:
                        if self._app:
                            with self._app.app_context():
                                self._alert_manager.create_alert(
                                    alert_type=threat['alert_type'],
                                    severity=threat['severity'],
                                    src_ip=threat.get('source_ip'),
                                    dst_ip=threat.get('destination_ip'),
                                    description=threat['description'],
                                )
                if self._app:
                    with self._app.app_context():
                        stat = TrafficStat(
                            packets_per_second=stats['packets_per_second'],
                            bytes_per_second=stats['bytes_per_second'],
                            total_packets=stats['total_packets'],
                            total_bytes=stats['total_bytes'],
                            unique_ips=stats['unique_ips'],
                            protocol_counts=stats['protocol_counts'],
                        )
                        db.session.add(stat)
                        db.session.commit()
                try:
                    socketio.emit('stats_update', stats)
                except Exception:
                    pass
            except Exception:
                pass
            time.sleep(1)


monitor = NetworkMonitor()

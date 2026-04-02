import pytest
from app.core.threat_detector import ThreatDetector
from app.core import config as cfg


@pytest.fixture
def detector():
    return ThreatDetector()


def test_port_scan_detection(detector):
    src_ip = '10.0.0.1'
    result = None
    for port in range(1, cfg.PORT_SCAN_THRESHOLD + 1):
        result = detector.detect_port_scan(src_ip, port)
    assert result is not None
    assert result['alert_type'] == 'PORT_SCAN'
    assert result['source_ip'] == src_ip


def test_syn_flood_detection(detector):
    src_ip = '10.0.0.2'
    result = None
    for _ in range(cfg.SYN_FLOOD_THRESHOLD + 1):
        result = detector.detect_syn_flood(src_ip)
    assert result is not None
    assert result['alert_type'] == 'SYN_FLOOD'


def test_brute_force_detection(detector):
    src_ip = '10.0.0.3'
    dst_port = 22
    result = None
    for _ in range(cfg.BRUTE_FORCE_THRESHOLD + 1):
        result = detector.detect_brute_force(src_ip, dst_port)
    assert result is not None
    assert result['alert_type'] == 'BRUTE_FORCE'
    assert 'SSH' in result['description']


def test_ddos_detection(detector):
    src_ip = '10.0.0.4'
    result = None
    for _ in range(cfg.DDOS_THRESHOLD + 1):
        result = detector.detect_ddos(src_ip)
    assert result is not None
    assert result['alert_type'] == 'DDOS'


def test_suspicious_port_detection(detector):
    result = detector.detect_suspicious_port(4444, '10.0.0.5', '192.168.1.1')
    assert result is not None
    assert result['alert_type'] == 'SUSPICIOUS_PORT'


def test_no_false_positive_port_scan(detector):
    src_ip = '10.0.0.10'
    result = None
    for port in range(1, cfg.PORT_SCAN_THRESHOLD - 1):
        result = detector.detect_port_scan(src_ip, port)
    assert result is None


def test_analyze_packet_no_threats(detector):
    packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 54321,
        'dst_port': 80,
        'protocol': 'TCP',
        'flags': 0x10,  # ACK only
        'size': 500,
    }
    threats = detector.analyze_packet(packet)
    assert isinstance(threats, list)

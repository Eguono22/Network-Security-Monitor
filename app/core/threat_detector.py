import time
from collections import defaultdict
from . import config as cfg


class ThreatDetector:
    """
    Pure Python threat detection - no Flask context needed.
    Returns dicts describing detected threats.
    """

    def __init__(self):
        # {src_ip: {dst_port: [timestamps]}}
        self._port_scan_tracker = defaultdict(lambda: defaultdict(list))
        # {src_ip: [timestamps]}
        self._syn_flood_tracker = defaultdict(list)
        # {src_ip: {dst_port: [timestamps]}}
        self._brute_force_tracker = defaultdict(lambda: defaultdict(list))
        # {src_ip: [timestamps]}
        self._ddos_tracker = defaultdict(list)

    def analyze_packet(self, packet_info: dict) -> list:
        threats = []
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol', '')
        flags = packet_info.get('flags', 0)

        if not src_ip:
            return threats

        if dst_port:
            threat = self.detect_port_scan(src_ip, dst_port)
            if threat:
                threats.append(threat)

            if protocol == 'TCP' and dst_port in cfg.BRUTE_FORCE_PORTS:
                threat = self.detect_brute_force(src_ip, dst_port)
                if threat:
                    threats.append(threat)

            threat = self.detect_suspicious_port(dst_port, src_ip, dst_ip)
            if threat:
                threats.append(threat)

        if protocol == 'TCP' and isinstance(flags, int) and (flags & 0x02):
            threat = self.detect_syn_flood(src_ip)
            if threat:
                threats.append(threat)

        threat = self.detect_ddos(src_ip)
        if threat:
            threats.append(threat)

        return threats

    def detect_port_scan(self, src_ip, dst_port):
        now = time.time()
        window = cfg.PORT_SCAN_WINDOW
        cutoff = now - window
        ports = self._port_scan_tracker[src_ip]
        if dst_port not in ports:
            ports[dst_port] = []
        ports[dst_port].append(now)
        ports[dst_port] = [t for t in ports[dst_port] if t > cutoff]
        active_ports = [p for p, ts in ports.items() if ts]
        if len(active_ports) >= cfg.PORT_SCAN_THRESHOLD:
            return {
                'alert_type': 'PORT_SCAN',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': None,
                'description': (
                    f'Port scan detected from {src_ip}: '
                    f'{len(active_ports)} unique ports in {window}s'
                ),
            }
        return None

    def detect_syn_flood(self, src_ip):
        now = time.time()
        cutoff = now - 1.0
        self._syn_flood_tracker[src_ip].append(now)
        self._syn_flood_tracker[src_ip] = [
            t for t in self._syn_flood_tracker[src_ip] if t > cutoff
        ]
        count = len(self._syn_flood_tracker[src_ip])
        if count >= cfg.SYN_FLOOD_THRESHOLD:
            return {
                'alert_type': 'SYN_FLOOD',
                'severity': 'CRITICAL',
                'source_ip': src_ip,
                'destination_ip': None,
                'description': f'SYN flood detected from {src_ip}: {count} SYN packets/sec',
            }
        return None

    def detect_brute_force(self, src_ip, dst_port):
        now = time.time()
        cutoff = now - 60.0
        attempts = self._brute_force_tracker[src_ip][dst_port]
        attempts.append(now)
        self._brute_force_tracker[src_ip][dst_port] = [t for t in attempts if t > cutoff]
        count = len(self._brute_force_tracker[src_ip][dst_port])
        if count >= cfg.BRUTE_FORCE_THRESHOLD:
            service = {22: 'SSH', 21: 'FTP', 3389: 'RDP', 5900: 'VNC'}.get(dst_port, str(dst_port))
            return {
                'alert_type': 'BRUTE_FORCE',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'destination_ip': None,
                'description': (
                    f'Brute force attack on {service} (port {dst_port}) '
                    f'from {src_ip}: {count} attempts/min'
                ),
            }
        return None

    def detect_ddos(self, src_ip):
        now = time.time()
        cutoff = now - 1.0
        self._ddos_tracker[src_ip].append(now)
        self._ddos_tracker[src_ip] = [t for t in self._ddos_tracker[src_ip] if t > cutoff]
        count = len(self._ddos_tracker[src_ip])
        if count >= cfg.DDOS_THRESHOLD:
            return {
                'alert_type': 'DDOS',
                'severity': 'CRITICAL',
                'source_ip': src_ip,
                'destination_ip': None,
                'description': f'DDoS attack detected from {src_ip}: {count} packets/sec',
            }
        return None

    def detect_dns_tunneling(self, packet_info: dict):
        dst_port = packet_info.get('dst_port')
        size = packet_info.get('size', 0)
        src_ip = packet_info.get('src_ip', '')
        if dst_port == 53 and size > cfg.DNS_TUNNEL_PAYLOAD_SIZE:
            return {
                'alert_type': 'DNS_TUNNELING',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': packet_info.get('dst_ip', ''),
                'description': (
                    f'Possible DNS tunneling from {src_ip}: '
                    f'oversized DNS query ({size} bytes)'
                ),
            }
        return None

    def detect_suspicious_port(self, dst_port, src_ip, dst_ip):
        if dst_port in cfg.SUSPICIOUS_PORTS:
            return {
                'alert_type': 'SUSPICIOUS_PORT',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'description': (
                    f'Connection to suspicious port {dst_port} '
                    f'from {src_ip} to {dst_ip}'
                ),
            }
        return None

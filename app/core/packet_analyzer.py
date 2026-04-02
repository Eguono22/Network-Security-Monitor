import time
import random
import threading
from collections import defaultdict, deque

from app.core.utils import utcnow as _utcnow

SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    pass

SIMULATED_IPS = (
    ['192.168.1.' + str(i) for i in range(1, 20)]
    + ['10.0.0.' + str(i) for i in range(1, 10)]
    + ['172.16.0.' + str(i) for i in range(1, 5)]
)

SUSPICIOUS_IPS = ['45.33.32.156', '198.51.100.1', '203.0.113.42']
COMMON_PORTS = [80, 443, 22, 25, 53, 3306, 5432, 8080, 8443, 21]
PROTOCOLS = ['TCP', 'UDP', 'ICMP']


class PacketAnalyzer:
    def __init__(self):
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._packet_count = 0
        self._byte_count = 0
        self._protocol_counts = defaultdict(int)
        self._ip_counts = defaultdict(int)
        self._port_counts = defaultdict(int)
        self._recent_packets = deque(maxlen=200)
        self._last_stat_time = time.time()
        self._last_packet_count = 0
        self._last_byte_count = 0
        self._pps = 0.0
        self._bps = 0.0
        self._packet_callbacks = []

    def add_packet_callback(self, cb):
        self._packet_callbacks.append(cb)

    def start_capture(self, interface=None):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface,),
            daemon=True
        )
        self._thread.start()

    def stop_capture(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def _capture_loop(self, interface):
        if SCAPY_AVAILABLE:
            try:
                sniff(
                    iface=interface,
                    prn=self._process_scapy_packet,
                    store=False,
                    stop_filter=lambda _: not self._running
                )
            except Exception:
                self._simulate_loop()
        else:
            self._simulate_loop()

    def _process_scapy_packet(self, pkt):
        try:
            info = {}
            if IP in pkt:
                info['src_ip'] = pkt[IP].src
                info['dst_ip'] = pkt[IP].dst
                info['size'] = len(pkt)
                if TCP in pkt:
                    info['protocol'] = 'TCP'
                    info['src_port'] = pkt[TCP].sport
                    info['dst_port'] = pkt[TCP].dport
                    info['flags'] = pkt[TCP].flags
                elif UDP in pkt:
                    info['protocol'] = 'UDP'
                    info['src_port'] = pkt[UDP].sport
                    info['dst_port'] = pkt[UDP].dport
                elif ICMP in pkt:
                    info['protocol'] = 'ICMP'
                else:
                    info['protocol'] = 'OTHER'
                info['timestamp'] = _utcnow().isoformat()
                self._record_packet(info)
        except Exception:
            pass

    def _simulate_loop(self):
        while self._running:
            count = random.randint(5, 20)
            for _ in range(count):
                info = self._generate_simulated_packet()
                self._record_packet(info)
            time.sleep(0.1)

    def _generate_simulated_packet(self):
        src_ip = random.choice(SIMULATED_IPS + SUSPICIOUS_IPS[:1])
        dst_ip = random.choice(SIMULATED_IPS)
        protocol = random.choice(PROTOCOLS)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(COMMON_PORTS)
        size = random.randint(64, 1500)
        flags = 0
        if protocol == 'TCP':
            flags = random.choice([0x02, 0x10, 0x18, 0x11])
        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'flags': flags,
            'size': size,
            'timestamp': _utcnow().isoformat(),
        }

    def _record_packet(self, info):
        with self._lock:
            self._packet_count += 1
            size = info.get('size', 0)
            self._byte_count += size
            proto = info.get('protocol', 'OTHER')
            self._protocol_counts[proto] += 1
            src = info.get('src_ip', '')
            if src:
                self._ip_counts[src] += 1
            dst_port = info.get('dst_port')
            if dst_port:
                self._port_counts[dst_port] += 1
            self._recent_packets.append(info)
            now = time.time()
            elapsed = now - self._last_stat_time
            if elapsed >= 1.0:
                self._pps = (self._packet_count - self._last_packet_count) / elapsed
                self._bps = (self._byte_count - self._last_byte_count) / elapsed
                self._last_packet_count = self._packet_count
                self._last_byte_count = self._byte_count
                self._last_stat_time = now
        for cb in self._packet_callbacks:
            try:
                cb(info)
            except Exception:
                pass

    def get_stats(self):
        with self._lock:
            return {
                'packets_per_second': round(self._pps, 2),
                'bytes_per_second': round(self._bps, 2),
                'total_packets': self._packet_count,
                'total_bytes': self._byte_count,
                'unique_ips': len(self._ip_counts),
                'protocol_counts': dict(self._protocol_counts),
            }

    def get_recent_packets(self, n=100):
        with self._lock:
            packets = list(self._recent_packets)
        return packets[-n:]

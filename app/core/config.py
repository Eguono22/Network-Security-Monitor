# Detection thresholds
PORT_SCAN_THRESHOLD = 10       # unique ports in time window
PORT_SCAN_WINDOW = 60          # seconds
SYN_FLOOD_THRESHOLD = 100      # SYN packets per second from one IP
BRUTE_FORCE_THRESHOLD = 5      # failed attempts per minute
BRUTE_FORCE_PORTS = [22, 21, 3389, 5900]  # SSH, FTP, RDP, VNC
DDOS_THRESHOLD = 1000          # packets per second from single IP
DNS_TUNNEL_PAYLOAD_SIZE = 100  # bytes (suspicious DNS query size)
SUSPICIOUS_PORTS = [4444, 1337, 31337, 12345, 6667]  # common backdoor ports

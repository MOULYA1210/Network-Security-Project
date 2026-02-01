from scapy.layers.inet import IP, TCP
from collections import defaultdict
import time

# VERY LOW thresholds for testing
DOS_THRESHOLD = 2
PORT_SCAN_THRESHOLD = 3
TIME_WINDOW = 15

packet_count = defaultdict(int)
port_scan_tracker = defaultdict(set)
start_time = time.time()

def detect_intrusion(packet):
    global start_time

    if IP not in packet:
        return

    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    print(f"[DEBUG] Packet from {src_ip}")  # 👈 DEBUG LINE

    # ---- DoS Detection ----
    if packet_count[src_ip] >= DOS_THRESHOLD:
        print(f"[ALERT] DoS detected from {src_ip}")

    # ---- Port Scan Detection ----
    if TCP in packet:
        port_scan_tracker[src_ip].add(packet[TCP].dport)

        if len(port_scan_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
            print(f"[ALERT] Port Scan detected from {src_ip}")

    # Reset window
    if time.time() - start_time > TIME_WINDOW:
        packet_count.clear()
        port_scan_tracker.clear()
        start_time = time.time()
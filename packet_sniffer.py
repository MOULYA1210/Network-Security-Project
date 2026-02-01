from scapy.all import sniff, IP, TCP
from ids import detect_intrusion

print("[*] Packet Sniffer + Mini IDS Started")
print("[*] Listening on ALL interfaces\n")

def packet_callback(packet):
    detect_intrusion(packet)

sniff(prn=packet_callback, store=False)
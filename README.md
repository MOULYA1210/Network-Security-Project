Project: Packet Sniffer with Mini Intrusion Detection System
Developed a Python‑based packet sniffer using Scapy to capture and analyze live network traffic.
Implemented a rule‑based Intrusion Detection System (IDS) to detect DoS attacks and port scanning attempts in real time.
Designed threshold‑based anomaly detection with time‑windowed analysis.
Logged network activity and security alerts for monitoring and forensic analysis.
Addressed Windows packet capture limitations using loopback traffic for reliable detection.

Tech Stack: Python, Scapy, Networking (TCP/IP), Cyber Security

1. PLATFORM & ENVIRONMENT
-Operating System
Windows (10/11)
-Programming Language
Python 3.13

2. TOOLS & SOFTWARE USED
🔹 1. Python
🔹 2. Scapy
🔹 3. Npcap / WinPcap (Background Tool)
🔹 4. Command Prompt (Administrator)

3. PROJECT ARCHITECTURE (BIG PICTURE)
Network Traffic
      ↓
Scapy Sniffer
      ↓
Packet Callback Function
      ↓
IDS Logic (detect_intrusion)
      ↓
ALERT / LOG

4. FILE STRUCTURE
Network_Security_Project
packet_sniffer.py   → captures traffic
ids.py              → detects attacks
packets.log         → traffic logs

5. PACKET SNIFFER (packet_sniffer.py)
Purpose:Captures live network packets and forwards them to IDS

6. IDS MODULE (ids.py)
Purpose:Detects suspicious behavior based on traffic patterns

7. ATTACK DETECTION LOGIC
  A. DoS ATTACK DETECTION
Too many packets from one IP in short time = DoS
  B. PORT SCAN DETECTION
Attacker tries many ports to find open services


“This project implements a real‑time packet sniffer and mini intrusion detection system using Python and Scapy to detect DoS attacks and port scanning based on traffic behavior analysis.”

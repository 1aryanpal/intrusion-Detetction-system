import json
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw

# Load existing signatures.json
with open("signatures.json", "r") as f:
    signatures = json.load(f)

os.makedirs("logs", exist_ok=True)

def log_alert(alert):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert["timestamp"] = timestamp

    # JSON log
    with open("logs/alerts.jsonl", "a") as f:
        json.dump(alert, f)
        f.write("\n")

    # Plain text log 
    line = f"[{timestamp}] {alert['severity']} - {alert['name']} from {alert['src_ip']} (Details: {alert.get('details', '')})"
    with open("logs/alerts.txt", "a") as f:
        f.write(line + "\n")

    print(line)

def check_signatures(packet):
    if IP not in packet:
        return
    ip_src = packet[IP].src
    for sig in signatures:
        name = sig.get("name", "Unknown")
        severity = sig.get("severity", "low").upper()
        match = sig.get("match", {})

        triggered = False
        details = ""

        if TCP in packet and "dst_port" in match and packet[TCP].dport in match["dst_port"]:
            triggered = True
            details = f"Destination port {packet[TCP].dport} matched"

        if "protocol" in match and packet[IP].proto in match["protocol"]:
            triggered = True
            details = f"Protocol {packet[IP].proto} matched"

        if Raw in packet and "payload_keywords" in match:
            payload = packet[Raw].load.decode(errors="ignore").lower()
            for keyword in match["payload_keywords"]:
                if keyword.lower() in payload:
                    triggered = True
                    details = f"Keyword '{keyword}' found in payload"
                    break

        if triggered:
            log_alert({
                "severity": severity,
                "name": name,
                "src_ip": ip_src,
                "dst_port": packet[TCP].dport if TCP in packet else None,
                "details": details
            })

def log_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        info = f"{ip_src} -> {ip_dst} | Protocol: {proto}"
        with open("logs/packets.txt", "a") as f:
            f.write(info + "\n")

def log_alert_txt(alert_str):
    with open("logs/alerts.txt", "a") as f:
        f.write(alert_str + "\n")


def process_packet(packet):
    log_packet(packet)       # log normal packets
    check_signatures(packet) # check for threats


if __name__ == "__main__":
    print("[*] Starting packet capture...")
    sniff(filter="ip", prn=process_packet, store=False)

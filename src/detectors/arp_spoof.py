"""ARP Spoofing and Cache Poisoning Anomaly Detector."""

from typing import Dict, List, Optional
from src.parser.arp import ARPPacket


class ARPSpoofAlert:
    def __init__(self, ip: str, old_mac: str, new_mac: str, timestamp: float):
        self.ip = ip
        self.old_mac = old_mac
        self.new_mac = new_mac
        self.timestamp = timestamp
        self.message = f"ARP Poisoning Detected: IP '{ip}' mapped to new MAC '{new_mac}' (Previously: '{old_mac}')"


class ARPSpoofDetector:
    """Maintains an IP-to-MAC resolution table and flags conflicting associations."""

    def __init__(self):
        self.ip_mac_table: Dict[str, str] = {}
        self.alerts: List[ARPSpoofAlert] = []

    def inspect_arp(self, arp: ARPPacket, timestamp: float = 0.0) -> Optional[ARPSpoofAlert]:
        sender_ip = arp.sender_ip
        sender_mac = arp.sender_mac

        # Ignore invalid/broadcast IPs
        if sender_ip in ("0.0.0.0", "255.255.255.255"):
            return None

        if sender_ip in self.ip_mac_table:
            known_mac = self.ip_mac_table[sender_ip]
            if known_mac.lower() != sender_mac.lower():
                alert = ARPSpoofAlert(sender_ip, known_mac, sender_mac, timestamp)
                self.alerts.append(alert)
                return alert
        else:
            self.ip_mac_table[sender_ip] = sender_mac

        return None

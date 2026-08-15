"""DNS Tunneling and Covert Channel Data Exfiltration Detector."""

from typing import List, Optional
from src.parser.dns import DNSPacket


class DNSTunnelAlert:
    def __init__(self, query_name: str, query_type: str, entropy: float, query_length: int, reason: str):
        self.query_name = query_name
        self.query_type = query_type
        self.entropy = entropy
        self.query_length = query_length
        self.reason = reason
        self.message = f"DNS Tunneling / Data Exfiltration: {query_name} ({reason} | Entropy: {entropy:.2f})"


class DNSTunnelDetector:
    """Detects algorithmic DGA domains and Base32/Hex encoded DNS covert data exfiltration."""

    def __init__(self, entropy_threshold: float = 3.65, length_threshold: int = 45):
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.alerts: List[DNSTunnelAlert] = []

    def inspect_dns(self, dns: DNSPacket) -> List[DNSTunnelAlert]:
        detected = []
        for q in dns.queries:
            entropy = q.entropy
            length = len(q.qname)

            is_high_entropy = entropy >= self.entropy_threshold and length >= 20
            is_oversized_payload = length >= self.length_threshold
            is_txt_abuse = q.qtype_name == "TXT" and entropy >= 3.5

            if is_high_entropy or is_oversized_payload or is_txt_abuse:
                reasons = []
                if is_high_entropy:
                    reasons.append(f"High Entropy ({entropy:.2f} >= {self.entropy_threshold})")
                if is_oversized_payload:
                    reasons.append(f"Abnormal Query Length ({length} chars)")
                if is_txt_abuse:
                    reasons.append("Suspicious High-Entropy TXT Payload")

                alert = DNSTunnelAlert(q.qname, q.qtype_name, entropy, length, ", ".join(reasons))
                self.alerts.append(alert)
                detected.append(alert)

        return detected

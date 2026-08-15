"""TCP SYN Flood Denial-of-Service (DoS) Anomaly Detector."""

from collections import defaultdict
from typing import Dict, List, Optional
from src.parser.transport import TCPPacket


class SYNFloodAlert:
    def __init__(self, target_ip: str, target_port: int, syn_count: int, ack_count: int, syn_ack_ratio: float):
        self.target_ip = target_ip
        self.target_port = target_port
        self.syn_count = syn_count
        self.ack_count = ack_count
        self.syn_ack_ratio = syn_ack_ratio
        self.message = (
            f"TCP SYN Flood Detected on {target_ip}:{target_port} "
            f"({syn_count} SYNs vs {ack_count} ACKs | Ratio: {syn_ack_ratio:.1f}x)"
        )


class SYNFloodDetector:
    """Tracks SYN-to-ACK ratios per destination socket to detect half-open flooding."""

    def __init__(self, min_syn_threshold: int = 20, ratio_threshold: float = 4.0):
        self.min_syn_threshold = min_syn_threshold
        self.ratio_threshold = ratio_threshold
        self.syn_counters: Dict[str, int] = defaultdict(int)
        self.ack_counters: Dict[str, int] = defaultdict(int)
        self.alerts: List[SYNFloodAlert] = []

    def inspect_tcp(self, dst_ip: str, tcp: TCPPacket) -> Optional[SYNFloodAlert]:
        socket_key = f"{dst_ip}:{tcp.dst_port}"

        if tcp.is_syn and not tcp.is_ack:
            self.syn_counters[socket_key] += 1
        elif tcp.is_ack:
            self.ack_counters[socket_key] += 1

        syn_count = self.syn_counters[socket_key]
        ack_count = max(1, self.ack_counters[socket_key])
        ratio = syn_count / ack_count

        if syn_count >= self.min_syn_threshold and ratio >= self.ratio_threshold:
            # Trigger once per threshold breach
            alert = SYNFloodAlert(dst_ip, tcp.dst_port, syn_count, ack_count, ratio)
            self.alerts.append(alert)
            return alert

        return None

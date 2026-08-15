"""Bidirectional 5-Tuple Network Flow Reconstructor."""

from typing import Dict, List, Optional, Tuple


class NetworkFlow:
    """Represents a bidirectional conversation session between two endpoints."""

    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.forward_packets = 0
        self.forward_bytes = 0
        self.reverse_packets = 0
        self.reverse_bytes = 0
        self.start_time: float = 0.0
        self.last_time: float = 0.0
        self.tcp_state: str = "INIT"

    @property
    def total_packets(self) -> int:
        return self.forward_packets + self.reverse_packets

    @property
    def total_bytes(self) -> int:
        return self.forward_bytes + self.reverse_bytes

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    def record_packet(self, is_forward: bool, length: int, timestamp: float, tcp_flags: Optional[str] = None):
        if self.forward_packets == 0 and self.reverse_packets == 0:
            self.start_time = timestamp
        self.last_time = timestamp

        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += length
        else:
            self.reverse_packets += 1
            self.reverse_bytes += length

        if tcp_flags:
            if "SYN" in tcp_flags and "ACK" not in tcp_flags:
                self.tcp_state = "SYN_SENT"
            elif "SYN" in tcp_flags and "ACK" in tcp_flags:
                self.tcp_state = "SYN_RECEIVED"
            elif "ACK" in tcp_flags and self.tcp_state == "SYN_RECEIVED":
                self.tcp_state = "ESTABLISHED"
            elif "FIN" in tcp_flags or "RST" in tcp_flags:
                self.tcp_state = "CLOSED"


class FlowReconstructor:
    """Tracks active 5-tuple conversations and aggregates packet metrics."""

    def __init__(self):
        self.flows: Dict[str, NetworkFlow] = {}

    def get_flow_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> Tuple[str, bool]:
        forward_key = f"{protocol}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        reverse_key = f"{protocol}:{dst_ip}:{dst_port}->{src_ip}:{src_port}"

        if forward_key in self.flows:
            return forward_key, True
        if reverse_key in self.flows:
            return reverse_key, False

        return forward_key, True

    def ingest_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        length: int,
        timestamp: float = 0.0,
        tcp_flags: Optional[str] = None,
    ) -> NetworkFlow:
        key, is_forward = self.get_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)
        if key not in self.flows:
            self.flows[key] = NetworkFlow(src_ip, src_port, dst_ip, dst_port, protocol)

        flow = self.flows[key]
        flow.record_packet(is_forward, length, timestamp, tcp_flags)
        return flow

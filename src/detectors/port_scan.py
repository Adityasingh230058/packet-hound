"""Port Scanning and Lateral Subnet Reconnaissance Detector."""

from collections import defaultdict
from typing import Dict, List, Optional, Set


class PortScanAlert:
    def __init__(self, scanner_ip: str, scan_type: str, target_count: int, targets_summary: str):
        self.scanner_ip = scanner_ip
        self.scan_type = scan_type
        self.target_count = target_count
        self.targets_summary = targets_summary
        self.message = f"Network Reconnaissance Detected: Host '{scanner_ip}' performed {scan_type} ({targets_summary})"


class PortScanDetector:
    """Detects both Vertical Port Scans (1 host, many ports) and Horizontal Subnet Sweeps (many hosts, 1 port)."""

    def __init__(self, vertical_threshold: int = 15, horizontal_threshold: int = 10):
        self.vertical_threshold = vertical_threshold
        self.horizontal_threshold = horizontal_threshold
        # scanner_ip -> target_ip -> set of ports
        self.probes: Dict[str, Dict[str, Set[int]]] = defaultdict(lambda: defaultdict(set))
        self.alerts: List[PortScanAlert] = []

    def inspect_connection(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[PortScanAlert]:
        self.probes[src_ip][dst_ip].add(dst_port)

        # 1. Vertical Port Scan Check (Single target, multiple distinct ports)
        target_ports = self.probes[src_ip][dst_ip]
        if len(target_ports) >= self.vertical_threshold:
            alert = PortScanAlert(
                src_ip,
                "Vertical Port Scan (Nmap/Masscan)",
                len(target_ports),
                f"{len(target_ports)} ports scanned on {dst_ip}",
            )
            self.alerts.append(alert)
            return alert

        # 2. Horizontal Subnet Sweep Check (Multiple target IPs probed by one source)
        target_ips = self.probes[src_ip]
        if len(target_ips) >= self.horizontal_threshold:
            alert = PortScanAlert(
                src_ip,
                "Horizontal Subnet Sweep",
                len(target_ips),
                f"{len(target_ips)} distinct hosts probed in subnet",
            )
            self.alerts.append(alert)
            return alert

        return None

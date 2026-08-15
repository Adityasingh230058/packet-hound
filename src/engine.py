"""Central Packet Hound Network Analysis and Anomaly Detection Engine."""

from typing import Any, Dict, List, Optional
from src.detectors.arp_spoof import ARPSpoofAlert, ARPSpoofDetector
from src.detectors.dns_tunnel import DNSTunnelAlert, DNSTunnelDetector
from src.detectors.port_scan import PortScanAlert, PortScanDetector
from src.detectors.syn_flood import SYNFloodAlert, SYNFloodDetector
from src.flow.reconstructor import FlowReconstructor, NetworkFlow
from src.parser.arp import ARPPacket
from src.parser.dns import DNSPacket
from src.parser.ethernet import EthernetFrame
from src.parser.ip import IPv4Packet, IPv6Packet
from src.parser.tls import TLSRecord
from src.parser.transport import TCPPacket, UDPPacket


class PacketSummary:
    """Consolidated forensic summary of a dissected packet."""

    def __init__(
        self,
        timestamp: float,
        frame_len: int,
        src_mac: str,
        dst_mac: str,
        network_proto: str,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        transport_proto: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        info: str = "",
        app_proto: Optional[str] = None,
    ):
        self.timestamp = timestamp
        self.frame_len = frame_len
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.network_proto = network_proto
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.transport_proto = transport_proto
        self.src_port = src_port
        self.dst_port = dst_port
        self.info = info
        self.app_proto = app_proto


class PacketHoundEngine:
    """Dissects raw packets, tracks active flows, and executes threat detectors."""

    def __init__(self):
        self.arp_detector = ARPSpoofDetector()
        self.syn_detector = SYNFloodDetector()
        self.dns_detector = DNSTunnelDetector()
        self.scan_detector = PortScanDetector()
        self.flow_tracker = FlowReconstructor()
        self.all_alerts: List[Any] = []
        self.packet_summaries: List[PacketSummary] = []

    def process_raw_packet(self, raw_bytes: bytes, timestamp: float = 0.0) -> Optional[PacketSummary]:
        eth = EthernetFrame.parse(raw_bytes)
        if not eth:
            return None

        summary = PacketSummary(
            timestamp=timestamp,
            frame_len=len(raw_bytes),
            src_mac=eth.src_mac,
            dst_mac=eth.dst_mac,
            network_proto="UNKNOWN",
        )

        # 1. ARP Protocol
        if eth.ethertype == EthernetFrame.ETHERTYPE_ARP:
            arp = ARPPacket.parse(eth.payload)
            if arp:
                summary.network_proto = "ARP"
                summary.src_ip = arp.sender_ip
                summary.dst_ip = arp.target_ip
                op_str = "Request" if arp.opcode == 1 else "Reply"
                summary.info = f"ARP {op_str} who has {arp.target_ip}? Tell {arp.sender_ip}"

                alert = self.arp_detector.inspect_arp(arp, timestamp)
                if alert:
                    self.all_alerts.append(alert)

        # 2. IPv4 Protocol
        elif eth.ethertype == EthernetFrame.ETHERTYPE_IPV4:
            ip = IPv4Packet.parse(eth.payload)
            if ip:
                summary.network_proto = "IPv4"
                summary.src_ip = ip.src_ip
                summary.dst_ip = ip.dst_ip

                # A. TCP
                if ip.protocol == IPv4Packet.PROTO_TCP:
                    tcp = TCPPacket.parse(ip.payload)
                    if tcp:
                        summary.transport_proto = "TCP"
                        summary.src_port = tcp.src_port
                        summary.dst_port = tcp.dst_port
                        summary.info = f"{tcp.src_port} -> {tcp.dst_port} [{tcp.flags_str}] Seq={tcp.seq_num} Win={tcp.window_size}"

                        # Flow Tracking
                        self.flow_tracker.ingest_packet(
                            ip.src_ip, tcp.src_port, ip.dst_ip, tcp.dst_port, "TCP", len(raw_bytes), timestamp, tcp.flags_str
                        )

                        # Threat Checks
                        syn_alert = self.syn_detector.inspect_tcp(ip.dst_ip, tcp)
                        if syn_alert:
                            self.all_alerts.append(syn_alert)

                        scan_alert = self.scan_detector.inspect_connection(ip.src_ip, ip.dst_ip, tcp.dst_port)
                        if scan_alert:
                            self.all_alerts.append(scan_alert)

                        # TLS Dissection (Port 443 or TLS Handshake)
                        if tcp.dst_port == 443 or tcp.src_port == 443:
                            tls = TLSRecord.parse(tcp.payload)
                            if tls:
                                summary.app_proto = "TLS"
                                if tls.server_name:
                                    summary.info = f"TLS ClientHello SNI={tls.server_name} JA3={tls.ja3_fingerprint[:8]}"

                # B. UDP
                elif ip.protocol == IPv4Packet.PROTO_UDP:
                    udp = UDPPacket.parse(ip.payload)
                    if udp:
                        summary.transport_proto = "UDP"
                        summary.src_port = udp.src_port
                        summary.dst_port = udp.dst_port
                        summary.info = f"{udp.src_port} -> {udp.dst_port} Len={udp.length}"

                        # Flow Tracking
                        self.flow_tracker.ingest_packet(
                            ip.src_ip, udp.src_port, ip.dst_ip, udp.dst_port, "UDP", len(raw_bytes), timestamp
                        )

                        # DNS Dissection (Port 53)
                        if udp.dst_port == 53 or udp.src_port == 53:
                            dns = DNSPacket.parse(udp.payload)
                            if dns:
                                summary.app_proto = "DNS"
                                q_names = [f"{q.qtype_name} {q.qname}" for q in dns.queries]
                                summary.info = f"DNS {'Response' if dns.is_response else 'Query'} ({', '.join(q_names)})"

                                dns_alerts = self.dns_detector.inspect_dns(dns)
                                self.all_alerts.extend(dns_alerts)

        self.packet_summaries.append(summary)
        return summary

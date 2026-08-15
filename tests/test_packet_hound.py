import struct
import sys
from pathlib import Path

# Ensure root is in sys.path for Linux CI / Pytest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from src.detectors.arp_spoof import ARPSpoofDetector
from src.detectors.dns_tunnel import DNSTunnelDetector
from src.detectors.port_scan import PortScanDetector
from src.detectors.syn_flood import SYNFloodDetector
from src.flow.reconstructor import FlowReconstructor
from src.parser.arp import ARPPacket
from src.parser.dns import DNSPacket, DNSQuery
from src.parser.ethernet import EthernetFrame
from src.parser.ip import IPv4Packet, IPv6Packet
from src.parser.tls import TLSRecord
from src.parser.transport import TCPPacket, UDPPacket
from src.pcap.reader import PCAPReader, PCAPWriter


# 1. Ethernet Tests
def test_ethernet_frame_parsing():
    raw_eth = bytes.fromhex("ffffffffffff0011223344550800") + b"PAYLOAD_DATA"
    frame = EthernetFrame.parse(raw_eth)
    assert frame is not None
    assert frame.dst_mac == "ff:ff:ff:ff:ff:ff"
    assert frame.src_mac == "00:11:22:33:44:55"
    assert frame.ethertype == EthernetFrame.ETHERTYPE_IPV4
    assert frame.vlan_id is None
    assert frame.payload == b"PAYLOAD_DATA"


def test_ethernet_vlan_8021q_parsing():
    # 802.1Q tag (0x8100), VLAN ID 100 (0x0064), encapsulated ethertype 0x0800
    raw_vlan = bytes.fromhex("ffffffffffff001122334455810000640800") + b"VLAN_PAYLOAD"
    frame = EthernetFrame.parse(raw_vlan)
    assert frame is not None
    assert frame.vlan_id == 100
    assert frame.ethertype == EthernetFrame.ETHERTYPE_IPV4
    assert frame.payload == b"VLAN_PAYLOAD"


# 2. ARP & ARP Spoofing Tests
def test_arp_packet_parsing_and_spoof_detection():
    detector = ARPSpoofDetector()

    # Step 1: Legitimate gateway ARP reply
    arp1 = ARPPacket(1, 0x0800, 2, "00:50:56:c0:00:01", "192.168.1.1", "00:0c:29:ab:cd:ef", "192.168.1.50")
    alert1 = detector.inspect_arp(arp1)
    assert alert1 is None  # Initial mapping learned

    # Step 2: Attacker poisoned ARP reply for the same IP with different MAC
    arp2 = ARPPacket(1, 0x0800, 2, "00:11:22:33:44:55", "192.168.1.1", "00:0c:29:ab:cd:ef", "192.168.1.50")
    alert2 = detector.inspect_arp(arp2)
    assert alert2 is not None
    assert alert2.ip == "192.168.1.1"
    assert alert2.old_mac == "00:50:56:c0:00:01"
    assert alert2.new_mac == "00:11:22:33:44:55"


# 3. IPv4 and IPv6 Header Dissection Tests
def test_ipv4_packet_parsing():
    # Construct IPv4 Header: v4, ihl=5, proto=6 (TCP), src=192.168.1.10, dst=10.0.0.1
    raw_ip = bytes.fromhex("450000281234400040060000c0a8010a0a000001") + b"TCP_DATA"
    ip = IPv4Packet.parse(raw_ip)
    assert ip is not None
    assert ip.version == 4
    assert ip.src_ip == "192.168.1.10"
    assert ip.dst_ip == "10.0.0.1"
    assert ip.protocol == 6
    assert ip.ttl == 64
    assert ip.payload == b"TCP_DATA"


def test_ipv6_packet_parsing():
    # Construct IPv6 Header: v6, payload_len=8, next_header=17 (UDP), hop_limit=64
    src_ip6 = bytes.fromhex("20010db8000000000000000000000001")
    dst_ip6 = bytes.fromhex("20010db8000000000000000000000002")
    raw_ip6 = bytes.fromhex("6000000000081140") + src_ip6 + dst_ip6 + b"UDP_DATA"
    ip6 = IPv6Packet.parse(raw_ip6)
    assert ip6 is not None
    assert ip6.version == 6
    assert ip6.src_ip == "2001:db8::1"
    assert ip6.dst_ip == "2001:db8::2"
    assert ip6.next_header == 17
    assert ip6.payload == b"UDP_DATA"


# 4. TCP & UDP Transport Dissection Tests
def test_tcp_flags_dissection():
    # TCP header: src=443, dst=51234, seq=100, ack=200, offset=5, flags=0x12 (SYN-ACK)
    raw_tcp = bytes.fromhex("01bbc82200000064000000c85012ffff00000000") + b"PAYLOAD"
    tcp = TCPPacket.parse(raw_tcp)
    assert tcp is not None
    assert tcp.src_port == 443
    assert tcp.dst_port == 51234
    assert tcp.is_syn is True
    assert tcp.is_ack is True
    assert tcp.is_fin is False
    assert tcp.flags_str == "SYN,ACK"
    assert tcp.payload == b"PAYLOAD"


def test_udp_datagram_dissection():
    # UDP header: src=51234, dst=53, len=20 (8 header + 12 payload), checksum=0
    raw_udp = bytes.fromhex("c822003500140000") + b"DNS_PAYLOAD_"
    udp = UDPPacket.parse(raw_udp)
    assert udp is not None
    assert udp.src_port == 51234
    assert udp.dst_port == 53
    assert udp.length == 20
    assert udp.payload == b"DNS_PAYLOAD_"


# 5. DNS Dissection & Shannon Entropy Tests
def test_dns_query_parsing_and_entropy():
    # Build query for standard domain vs high-entropy DGA/tunneling domain
    normal_q = DNSQuery("google.com", 1, 1)
    assert normal_q.qtype_name == "A"
    assert normal_q.entropy < 3.0

    dga_q = DNSQuery("v4x9j8m2k1p0q7z3w8b5c2d9e1f4g7h0.exfil.attacker-c2.com", 16, 1)
    assert dga_q.qtype_name == "TXT"
    assert dga_q.entropy > 4.2

    detector = DNSTunnelDetector(entropy_threshold=3.65)
    dns_pkt = DNSPacket(0x1234, 0x0100, False, 0, 0, [normal_q, dga_q])
    alerts = detector.inspect_dns(dns_pkt)
    assert len(alerts) == 1
    assert "High Entropy" in alerts[0].reason


# 6. TLS ClientHello SNI Extractor Tests
def test_tls_sni_extraction():
    # Build minimal TLS ClientHello record with SNI 'api.github.com'
    server_name = "api.github.com"
    sni_bytes = server_name.encode("utf-8")
    sni_ext = bytes.fromhex("0000") + struct.pack("!H", len(sni_bytes) + 5) + struct.pack("!HB", len(sni_bytes) + 3, 0) + struct.pack("!H", len(sni_bytes)) + sni_bytes
    exts = struct.pack("!H", len(sni_ext)) + sni_ext
    ciphers = struct.pack("!HH", 2, 0x1301)
    body = struct.pack("!H32sB", 0x0303, b"\x01" * 32, 0) + ciphers + b"\x01\x00" + exts
    hs_hdr = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body
    raw_tls = struct.pack("!BHH", 22, 0x0303, len(hs_hdr)) + hs_hdr

    tls = TLSRecord.parse(raw_tls)
    assert tls is not None
    assert tls.server_name == "api.github.com"
    assert len(tls.ja3_fingerprint) == 32  # Valid MD5 string


# 7. Threat Detector Tests (SYN Flood & Port Scanning)
def test_syn_flood_detector():
    detector = SYNFloodDetector(min_syn_threshold=10, ratio_threshold=3.0)
    syn_pkt = TCPPacket(50000, 80, 100, 0, 20, 0x02, 65535, 0, 0, b"")

    alert = None
    for i in range(12):
        alert = detector.inspect_tcp("192.168.1.100", syn_pkt)

    assert alert is not None
    assert alert.target_ip == "192.168.1.100"
    assert alert.syn_count == 12


def test_port_scan_detector():
    detector = PortScanDetector(vertical_threshold=10, horizontal_threshold=5)

    # Vertical scan: 1 target, 12 ports
    alert_v = None
    for port in range(1, 15):
        alert_v = detector.inspect_connection("10.0.0.5", "192.168.1.50", port)

    assert alert_v is not None
    assert alert_v.scan_type == "Vertical Port Scan (Nmap/Masscan)"

    # Horizontal sweep: 6 targets, 1 port (445)
    alert_h = None
    for ip_suffix in range(1, 8):
        alert_h = detector.inspect_connection("10.0.0.8", f"192.168.1.{ip_suffix}", 445)

    assert alert_h is not None
    assert alert_h.scan_type == "Horizontal Subnet Sweep"


# 8. 5-Tuple Flow Reconstruction Tests
def test_flow_reconstruction():
    reconstructor = FlowReconstructor()

    # Packet 1 (Forward SYN)
    f1 = reconstructor.ingest_packet("192.168.1.10", 54321, "8.8.8.8", 443, "TCP", 64, 100.0, "SYN")
    assert f1.forward_packets == 1
    assert f1.reverse_packets == 0
    assert f1.tcp_state == "SYN_SENT"

    # Packet 2 (Reverse SYN-ACK)
    f2 = reconstructor.ingest_packet("8.8.8.8", 443, "192.168.1.10", 54321, "TCP", 64, 100.05, "SYN,ACK")
    assert f2 is f1  # Same bidirectional flow session
    assert f1.forward_packets == 1
    assert f1.reverse_packets == 1
    assert f1.tcp_state == "SYN_RECEIVED"

    # Packet 3 (Forward ACK)
    reconstructor.ingest_packet("192.168.1.10", 54321, "8.8.8.8", 443, "TCP", 54, 100.10, "ACK")
    assert f1.tcp_state == "ESTABLISHED"
    assert f1.total_packets == 3
    assert f1.duration_seconds == pytest.approx(0.10, rel=1e-2)

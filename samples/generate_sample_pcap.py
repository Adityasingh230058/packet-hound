"""Generates realistic binary PCAP files containing both benign traffic and cyber attack patterns."""

import socket
import struct
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.pcap.reader import PCAPWriter


def build_ethernet_frame(dst_mac: str, src_mac: str, ethertype: int, payload: bytes) -> bytes:
    dst_b = bytes.fromhex(dst_mac.replace(":", ""))
    src_b = bytes.fromhex(src_mac.replace(":", ""))
    return struct.pack("!6s6sH", dst_b, src_b, ethertype) + payload


def build_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes) -> bytes:
    src_b = socket.inet_aton(src_ip)
    dst_b = socket.inet_aton(dst_ip)
    total_len = 20 + len(payload)
    v_ihl = (4 << 4) | 5
    hdr = struct.pack("!BBHHHBBH4s4s", v_ihl, 0, total_len, 54321, 0x4000, 64, proto, 0, src_b, dst_b)
    return hdr + payload


def build_tcp_packet(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    offset_res = (5 << 4)
    hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_res, flags, 65535, 0, 0)
    return hdr + payload


def build_udp_packet(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return hdr + payload


def build_arp_packet(opcode: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    s_mac_b = bytes.fromhex(sender_mac.replace(":", ""))
    s_ip_b = socket.inet_aton(sender_ip)
    t_mac_b = bytes.fromhex(target_mac.replace(":", ""))
    t_ip_b = socket.inet_aton(target_ip)
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, opcode, s_mac_b, s_ip_b, t_mac_b, t_ip_b)


def build_dns_query(tx_id: int, qname: str, qtype: int = 1) -> bytes:
    hdr = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    qname_bytes = b""
    for part in qname.split("."):
        qname_bytes += bytes([len(part)]) + part.encode("utf-8")
    qname_bytes += b"\x00"
    footer = struct.pack("!HH", qtype, 1)
    return hdr + qname_bytes + footer


def build_tls_client_hello(server_name: str) -> bytes:
    # Build minimal TLS ClientHello with SNI extension
    sni_bytes = server_name.encode("utf-8")
    sni_ext = struct.pack("!HHHB", 0, len(sni_bytes) + 5, len(sni_bytes) + 3, 0) + struct.pack("!H", len(sni_bytes)) + sni_bytes
    exts = struct.pack("!H", len(sni_ext)) + sni_ext

    # Ciphers (AES-GCM, CHACHA20)
    ciphers = struct.pack("!HH", 2, 0x1301)
    body = struct.pack("!H32sB", 0x0303, b"\x01" * 32, 0) + ciphers + b"\x01\x00" + exts

    hs_hdr = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body
    record = struct.pack("!BHH", 22, 0x0303, len(hs_hdr)) + hs_hdr
    return record


def generate_sample_pcap(filepath: str = "samples/network_traffic.pcap"):
    packets = []
    gw_mac = "00:50:56:c0:00:01"
    host_mac = "00:0c:29:ab:cd:ef"
    attacker_mac = "00:11:22:33:44:55"

    # 1. Normal ARP
    arp_req = build_arp_packet(1, host_mac, "192.168.1.50", "00:00:00:00:00:00", "192.168.1.1")
    packets.append(build_ethernet_frame("ff:ff:ff:ff:ff:ff", host_mac, 0x0806, arp_req))

    arp_rep = build_arp_packet(2, gw_mac, "192.168.1.1", host_mac, "192.168.1.50")
    packets.append(build_ethernet_frame(host_mac, gw_mac, 0x0806, arp_rep))

    # 2. ARP Spoofing Poisoning Attack (Attacker claims 192.168.1.1 has attacker_mac)
    arp_poison = build_arp_packet(2, attacker_mac, "192.168.1.1", host_mac, "192.168.1.50")
    packets.append(build_ethernet_frame(host_mac, attacker_mac, 0x0806, arp_poison))

    # 3. Normal DNS Query (github.com)
    dns_q = build_dns_query(0x1234, "github.com", 1)
    udp_dns = build_udp_packet(53210, 53, dns_q)
    ip_dns = build_ipv4_packet("192.168.1.50", "8.8.8.8", 17, udp_dns)
    packets.append(build_ethernet_frame(gw_mac, host_mac, 0x0800, ip_dns))

    # 4. DNS Tunneling Attack (High-Entropy Base32 data exfiltration)
    tunnel_q = build_dns_query(0x5678, "v4x9j8m2k1p0q7z3w8b5c2d9e1f4g7h0.exfil.attacker-c2.com", 16)
    udp_tunnel = build_udp_packet(53211, 53, tunnel_q)
    ip_tunnel = build_ipv4_packet("192.168.1.50", "8.8.8.8", 17, udp_tunnel)
    packets.append(build_ethernet_frame(gw_mac, host_mac, 0x0800, ip_tunnel))

    # 5. Normal HTTPS Session (TCP 3-Way Handshake + TLS ClientHello)
    tcp_syn = build_tcp_packet(49152, 443, 1000, 0, 0x02)  # SYN
    packets.append(build_ethernet_frame(gw_mac, host_mac, 0x0800, build_ipv4_packet("192.168.1.50", "140.82.121.4", 6, tcp_syn)))

    tcp_synack = build_tcp_packet(443, 49152, 5000, 1001, 0x12)  # SYN-ACK
    packets.append(build_ethernet_frame(host_mac, gw_mac, 0x0800, build_ipv4_packet("140.82.121.4", "192.168.1.50", 6, tcp_synack)))

    tcp_ack = build_tcp_packet(49152, 443, 1001, 5001, 0x10)  # ACK
    packets.append(build_ethernet_frame(gw_mac, host_mac, 0x0800, build_ipv4_packet("192.168.1.50", "140.82.121.4", 6, tcp_ack)))

    tls_hello = build_tls_client_hello("github.com")
    tcp_data = build_tcp_packet(49152, 443, 1001, 5001, 0x18, tls_hello)  # PSH-ACK + TLS
    packets.append(build_ethernet_frame(gw_mac, host_mac, 0x0800, build_ipv4_packet("192.168.1.50", "140.82.121.4", 6, tcp_data)))

    # 6. TCP SYN Flood Attack (25 rapid SYN packets to target port 80)
    for i in range(25):
        syn_flood = build_tcp_packet(10000 + i, 80, 2000 + i, 0, 0x02)
        ip_flood = build_ipv4_packet("10.0.0.99", "192.168.1.200", 6, syn_flood)
        packets.append(build_ethernet_frame(gw_mac, attacker_mac, 0x0800, ip_flood))

    # 7. Vertical Port Scan (18 distinct ports scanned on target host)
    target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 9000]
    for p in target_ports:
        scan_syn = build_tcp_packet(40000 + (p % 10000), p, 3000, 0, 0x02)
        ip_scan = build_ipv4_packet("185.220.101.5", "192.168.1.150", 6, scan_syn)
        packets.append(build_ethernet_frame(gw_mac, attacker_mac, 0x0800, ip_scan))

    out = Path(filepath)
    out.parent.mkdir(parents=True, exist_ok=True)
    PCAPWriter.write_pcap(str(out), packets)
    print(f"[+] Generated {len(packets)} sample binary PCAP packets at: {out.resolve()}")


if __name__ == "__main__":
    generate_sample_pcap()

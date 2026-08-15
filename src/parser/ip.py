"""IPv4 and IPv6 Packet Header Dissectors."""

import socket
import struct
from typing import Optional, Tuple


class IPv4Packet:
    """Represents a decoded IPv4 packet header."""

    PROTO_ICMP = 1
    PROTO_TCP = 6
    PROTO_UDP = 17

    def __init__(
        self,
        version: int,
        ihl: int,
        tos: int,
        total_length: int,
        identification: int,
        flags: int,
        fragment_offset: int,
        ttl: int,
        protocol: int,
        checksum: int,
        src_ip: str,
        dst_ip: str,
        payload: bytes,
    ):
        self.version = version
        self.ihl = ihl
        self.tos = tos
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload

    @classmethod
    def parse(cls, raw_bytes: bytes) -> Optional["IPv4Packet"]:
        if len(raw_bytes) < 20:
            return None

        v_ihl, tos, total_length, identification, flags_frag, ttl, proto, checksum, src, dst = struct.unpack(
            "!BBHHHBBH4s4s", raw_bytes[0:20]
        )

        version = v_ihl >> 4
        ihl = v_ihl & 0x0F
        if version != 4 or ihl < 5:
            return None

        header_length = ihl * 4
        if len(raw_bytes) < header_length:
            return None

        flags = flags_frag >> 13
        frag_offset = flags_frag & 0x1FFF

        src_ip = socket.inet_ntoa(src)
        dst_ip = socket.inet_ntoa(dst)
        payload = raw_bytes[header_length:total_length] if total_length > 0 else raw_bytes[header_length:]

        return cls(
            version,
            ihl,
            tos,
            total_length,
            identification,
            flags,
            frag_offset,
            ttl,
            proto,
            checksum,
            src_ip,
            dst_ip,
            payload,
        )


class IPv6Packet:
    """Represents a decoded IPv6 packet header."""

    def __init__(
        self,
        version: int,
        traffic_class: int,
        flow_label: int,
        payload_length: int,
        next_header: int,
        hop_limit: int,
        src_ip: str,
        dst_ip: str,
        payload: bytes,
    ):
        self.version = version
        self.traffic_class = traffic_class
        self.flow_label = flow_label
        self.payload_length = payload_length
        self.next_header = next_header
        self.hop_limit = hop_limit
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload

    @classmethod
    def parse(cls, raw_bytes: bytes) -> Optional["IPv6Packet"]:
        if len(raw_bytes) < 40:
            return None

        v_tc_fl, payload_len, next_header, hop_limit, src, dst = struct.unpack("!IHBB16s16s", raw_bytes[0:40])
        version = v_tc_fl >> 28
        if version != 6:
            return None

        traffic_class = (v_tc_fl >> 20) & 0xFF
        flow_label = v_tc_fl & 0xFFFFF

        src_ip = socket.inet_ntop(socket.AF_INET6, src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, dst)
        payload = raw_bytes[40 : 40 + payload_len]

        return cls(version, traffic_class, flow_label, payload_len, next_header, hop_limit, src_ip, dst_ip, payload)

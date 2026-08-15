"""Address Resolution Protocol (ARP) Dissector."""

import socket
import struct
from typing import Optional


class ARPPacket:
    """Represents an ARP request or reply packet."""

    OPCODE_REQUEST = 1
    OPCODE_REPLY = 2

    def __init__(
        self,
        hardware_type: int,
        protocol_type: int,
        opcode: int,
        sender_mac: str,
        sender_ip: str,
        target_mac: str,
        target_ip: str,
    ):
        self.hardware_type = hardware_type
        self.protocol_type = protocol_type
        self.opcode = opcode
        self.sender_mac = sender_mac
        self.sender_ip = sender_ip
        self.target_mac = target_mac
        self.target_ip = target_ip

    @classmethod
    def parse(cls, raw_bytes: bytes) -> Optional["ARPPacket"]:
        if len(raw_bytes) < 28:
            return None

        hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("!HHBBH", raw_bytes[0:8])
        if hw_size != 6 or proto_size != 4:
            return None

        sender_mac_raw = raw_bytes[8:14]
        sender_ip_raw = raw_bytes[14:18]
        target_mac_raw = raw_bytes[18:24]
        target_ip_raw = raw_bytes[24:28]

        sender_mac = ":".join(f"{b:02x}" for b in sender_mac_raw)
        sender_ip = socket.inet_ntoa(sender_ip_raw)
        target_mac = ":".join(f"{b:02x}" for b in target_mac_raw)
        target_ip = socket.inet_ntoa(target_ip_raw)

        return cls(hw_type, proto_type, opcode, sender_mac, sender_ip, target_mac, target_ip)

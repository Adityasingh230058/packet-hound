"""Ethernet II and 802.1Q VLAN Frame Dissector."""

import struct
from typing import Optional, Tuple


class EthernetFrame:
    """Represents a decoded Ethernet II frame."""

    ETHERTYPE_IPV4 = 0x0800
    ETHERTYPE_ARP = 0x0806
    ETHERTYPE_IPV6 = 0x86DD
    ETHERTYPE_VLAN = 0x8100

    def __init__(self, src_mac: str, dst_mac: str, ethertype: int, vlan_id: Optional[int], payload: bytes):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.ethertype = ethertype
        self.vlan_id = vlan_id
        self.payload = payload

    @classmethod
    def parse(cls, raw_bytes: bytes) -> Optional["EthernetFrame"]:
        if len(raw_bytes) < 14:
            return None

        dst_mac_raw = raw_bytes[0:6]
        src_mac_raw = raw_bytes[6:12]
        ethertype = struct.unpack("!H", raw_bytes[12:14])[0]

        dst_mac = ":".join(f"{b:02x}" for b in dst_mac_raw)
        src_mac = ":".join(f"{b:02x}" for b in src_mac_raw)

        payload_offset = 14
        vlan_id = None

        # Check for 802.1Q VLAN tag
        if ethertype == cls.ETHERTYPE_VLAN:
            if len(raw_bytes) < 18:
                return None
            vlan_tci = struct.unpack("!H", raw_bytes[14:16])[0]
            vlan_id = vlan_tci & 0x0FFF
            ethertype = struct.unpack("!H", raw_bytes[16:18])[0]
            payload_offset = 18

        payload = raw_bytes[payload_offset:]
        return cls(src_mac, dst_mac, ethertype, vlan_id, payload)

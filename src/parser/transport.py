"""TCP and UDP Transport Layer Dissectors."""

import struct
from typing import Optional


class TCPPacket:
    """Represents a decoded TCP segment header."""

    def __init__(
        self,
        src_port: int,
        dst_port: int,
        seq_num: int,
        ack_num: int,
        data_offset: int,
        flags: int,
        window_size: int,
        checksum: int,
        urgent_ptr: int,
        payload: bytes,
    ):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data_offset = data_offset
        self.flags = flags
        self.window_size = window_size
        self.checksum = checksum
        self.urgent_ptr = urgent_ptr
        self.payload = payload

    @property
    def is_fin(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def is_rst(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def is_psh(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def is_ack(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def is_urg(self) -> bool:
        return bool(self.flags & 0x20)

    @property
    def is_ece(self) -> bool:
        return bool(self.flags & 0x40)

    @property
    def is_cwr(self) -> bool:
        return bool(self.flags & 0x80)

    @property
    def flags_str(self) -> str:
        active = []
        if self.is_syn: active.append("SYN")
        if self.is_ack: active.append("ACK")
        if self.is_fin: active.append("FIN")
        if self.is_rst: active.append("RST")
        if self.is_psh: active.append("PSH")
        if self.is_urg: active.append("URG")
        return ",".join(active) if active else "NONE"

    @classmethod
    def parse(cls, raw_bytes: bytes) -> Optional["TCPPacket"]:
        if len(raw_bytes) < 20:
            return None

        src_port, dst_port, seq, ack, offset_reserved, flags, window, checksum, urg_ptr = struct.unpack(
            "!HHIIBBHHH", raw_bytes[0:20]
        )

        data_offset = (offset_reserved >> 4) * 4
        if len(raw_bytes) < data_offset:
            return None

        payload = raw_bytes[data_offset:]
        return cls(src_port, dst_port, seq, ack, data_offset, flags, window, checksum, urg_ptr, payload)


class UDPPacket:
    """Represents a decoded UDP datagram header."""

    def __init__(self, src_port: int, dst_port: int, length: int, checksum: int, payload: bytes):
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.checksum = checksum
        self.payload = payload

    @classmethod
    def parse(cls, raw_bytes: bytes) -> Optional["UDPPacket"]:
        if len(raw_bytes) < 8:
            return None

        src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw_bytes[0:8])
        payload = raw_bytes[8:length] if length > 8 else raw_bytes[8:]
        return cls(src_port, dst_port, length, checksum, payload)

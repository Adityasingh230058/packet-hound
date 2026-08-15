"""Pure Python Binary PCAP File Reader and Generator."""

import struct
import time
from typing import Generator, Optional, Tuple


class PCAPHeader:
    """Represents a standard 24-byte PCAP Global File Header."""

    MAGIC_MICROSECONDS = 0xA1B2C3D4
    MAGIC_NANOSECONDS = 0xA1B23C4D
    MAGIC_SWAPPED = 0xD4C3B2A1

    def __init__(self, magic: int, version_major: int, version_minor: int, snaplen: int, network: int):
        self.magic = magic
        self.version_major = version_major
        self.version_minor = version_minor
        self.snaplen = snaplen
        self.network = network  # 1 = Ethernet (LINKTYPE_ETHERNET)


class PCAPPacketRecord:
    """Represents an individual captured packet with 16-byte header."""

    def __init__(self, ts_sec: int, ts_usec: int, incl_len: int, orig_len: int, data: bytes):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.incl_len = incl_len
        self.orig_len = orig_len
        self.data = data

    @property
    def timestamp(self) -> float:
        return self.ts_sec + (self.ts_usec / 1_000_000.0)


class PCAPReader:
    """Reads raw packets from binary .pcap files without external C library dependencies."""

    @classmethod
    def read_file(cls, filepath: str) -> Generator[PCAPPacketRecord, None, None]:
        with open(filepath, "rb") as f:
            global_header_bytes = f.read(24)
            if len(global_header_bytes) < 24:
                return

            magic, v_maj, v_min, thiszone, sigfigs, snaplen, network = struct.unpack(
                "<IHHiIII", global_header_bytes
            )

            # Check byte order
            is_little_endian = magic in (PCAPHeader.MAGIC_MICROSECONDS, PCAPHeader.MAGIC_NANOSECONDS)
            fmt_prefix = "<" if is_little_endian else ">"

            while True:
                pkt_hdr_bytes = f.read(16)
                if len(pkt_hdr_bytes) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{fmt_prefix}IIII", pkt_hdr_bytes)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                yield PCAPPacketRecord(ts_sec, ts_usec, incl_len, orig_len, pkt_data)


class PCAPWriter:
    """Generates valid binary PCAP files for test suites and simulations."""

    @classmethod
    def write_pcap(cls, filepath: str, packet_payloads: list):
        with open(filepath, "wb") as f:
            # 24-byte PCAP Global Header: Magic(0xa1b2c3d4), v2.4, snaplen=65535, Ethernet=1
            global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            f.write(global_header)

            for i, raw_bytes in enumerate(packet_payloads):
                ts_sec = int(time.time()) + i
                ts_usec = 0
                incl_len = len(raw_bytes)
                orig_len = len(raw_bytes)

                pkt_header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
                f.write(pkt_header)
                f.write(raw_bytes)

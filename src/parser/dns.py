"""Domain Name System (DNS) Protocol Dissector and Entropy Calculator."""

import math
import struct
from collections import Counter
from typing import List, Optional, Tuple


class DNSQuery:
    def __init__(self, qname: str, qtype: int, qclass: int):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    @property
    def qtype_name(self) -> str:
        types = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}
        return types.get(self.qtype, f"TYPE{self.qtype}")

    @property
    def entropy(self) -> float:
        """Calculates Shannon entropy of the query string."""
        s = self.qname.lower().replace(".", "")
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())


class DNSPacket:
    """Represents a decoded DNS transaction header and query."""

    def __init__(
        self,
        transaction_id: int,
        flags: int,
        is_response: bool,
        opcode: int,
        rcode: int,
        queries: List[DNSQuery],
    ):
        self.transaction_id = transaction_id
        self.flags = flags
        self.is_response = is_response
        self.opcode = opcode
        self.rcode = rcode
        self.queries = queries

    @classmethod
    def parse(cls, raw_bytes: bytes) -> Optional["DNSPacket"]:
        if len(raw_bytes) < 12:
            return None

        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", raw_bytes[0:12])
        is_response = bool(flags & 0x8000)
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F

        offset = 12
        queries = []

        for _ in range(qdcount):
            qname_labels = []
            while offset < len(raw_bytes):
                length = raw_bytes[offset]
                if length == 0:
                    offset += 1
                    break
                # Pointer compression check
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1
                if offset + length > len(raw_bytes):
                    return None
                qname_labels.append(raw_bytes[offset : offset + length].decode("utf-8", errors="replace"))
                offset += length

            qname = ".".join(qname_labels)
            if offset + 4 <= len(raw_bytes):
                qtype, qclass = struct.unpack("!HH", raw_bytes[offset : offset + 4])
                offset += 4
                queries.append(DNSQuery(qname, qtype, qclass))

        return cls(tx_id, flags, is_response, opcode, rcode, queries)

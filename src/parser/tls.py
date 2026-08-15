"""TLS ClientHello Dissector and SNI Extractor."""

import hashlib
import struct
from typing import List, Optional


class TLSRecord:
    """Dissects TLS Handshake ClientHello to extract SNI (Server Name Indication)."""

    CONTENT_TYPE_HANDSHAKE = 22
    HANDSHAKE_TYPE_CLIENT_HELLO = 1

    def __init__(self, version: int, server_name: Optional[str], cipher_suites: List[int], ja3_fingerprint: str):
        self.version = version
        self.server_name = server_name
        self.cipher_suites = cipher_suites
        self.ja3_fingerprint = ja3_fingerprint

    @classmethod
    def parse(cls, raw_bytes: bytes) -> Optional["TLSRecord"]:
        if len(raw_bytes) < 5:
            return None

        content_type, tls_version, record_len = struct.unpack("!BHH", raw_bytes[0:5])
        if content_type != cls.CONTENT_TYPE_HANDSHAKE:
            return None

        if len(raw_bytes) < 5 + record_len or record_len < 4:
            return None

        handshake_type = raw_bytes[5]
        if handshake_type != cls.HANDSHAKE_TYPE_CLIENT_HELLO:
            return None

        offset = 9  # Skip handshake type and 3-byte length
        if len(raw_bytes) < offset + 34:
            return None

        client_version = struct.unpack("!H", raw_bytes[offset : offset + 2])[0]
        offset += 34  # Skip version (2) + random (32)

        if offset >= len(raw_bytes):
            return None

        # Session ID
        session_id_len = raw_bytes[offset]
        offset += 1 + session_id_len

        # Cipher Suites
        if offset + 2 > len(raw_bytes):
            return None
        cipher_suites_len = struct.unpack("!H", raw_bytes[offset : offset + 2])[0]
        offset += 2

        cipher_suites = []
        for _ in range(0, cipher_suites_len, 2):
            if offset + 2 <= len(raw_bytes):
                cs = struct.unpack("!H", raw_bytes[offset : offset + 2])[0]
                cipher_suites.append(cs)
                offset += 2

        # Compression Methods
        if offset < len(raw_bytes):
            comp_methods_len = raw_bytes[offset]
            offset += 1 + comp_methods_len

        # Extensions
        server_name = None
        extensions = []
        if offset + 2 <= len(raw_bytes):
            extensions_len = struct.unpack("!H", raw_bytes[offset : offset + 2])[0]
            offset += 2
            end_ext = offset + extensions_len

            while offset + 4 <= end_ext and offset + 4 <= len(raw_bytes):
                ext_type, ext_len = struct.unpack("!HH", raw_bytes[offset : offset + 4])
                offset += 4
                extensions.append(ext_type)

                # SNI extension is type 0x0000
                if ext_type == 0:
                    sni_offset = offset + 2  # Skip server_name_list_len
                    if sni_offset + 3 <= offset + ext_len:
                        name_type = raw_bytes[sni_offset]
                        name_len = struct.unpack("!H", raw_bytes[sni_offset + 1 : sni_offset + 3])[0]
                        sni_start = sni_offset + 3
                        if sni_start + name_len <= offset + ext_len:
                            server_name = raw_bytes[sni_start : sni_start + name_len].decode("utf-8", errors="replace")

                offset += ext_len

        # Calculate JA3 string and MD5 hash
        ja3_raw = f"{client_version},{'-'.join(str(c) for c in cipher_suites)},{'-'.join(str(e) for e in extensions)}"
        ja3_hash = hashlib.md5(ja3_raw.encode("utf-8")).hexdigest()

        return cls(client_version, server_name, cipher_suites, ja3_hash)

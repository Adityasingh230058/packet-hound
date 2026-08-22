# packet-hound — High-Performance Network Packet Dissector & Threat Detector

[![CI](https://github.com/Adityasingh230058/packet-hound/actions/workflows/ci.yml/badge.svg)](https://github.com/Adityasingh230058/packet-hound/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/Python-3.9%20|%203.10%20|%203.11%20|%203.12-brightgreen.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-12%20Passed%20(100%25)-success.svg)](tests/)
[![Code Style](https://img.shields.io/badge/Code%20Style-Black-000000.svg)](https://github.com/psf/black)

A pure-Python, zero-dependency network packet dissector, 5-tuple flow reconstructor, and network anomaly detection engine.

---

## Project Overview

`packet-hound` is a lightweight, zero-dependency network analysis engine designed to dissect raw network frames (Ethernet II, 802.1Q VLAN, ARP, IPv4/IPv6, TCP, UDP, DNS, and TLS) without relying on heavy external C libraries like `libpcap` or `WinPcap`. It parses binary `.pcap` files, reconstructs bidirectional TCP conversation streams, and flags active network attacks in real time.

---

## Network Anomalies & Threats Detected

* **ARP Poisoning & Spoofing**: Identifies conflicting MAC-to-IP associations and gratuitous ARP injection (Man-In-The-Middle attacks).
* **DNS Tunneling & Data Exfiltration**: Calculates Shannon entropy on domain queries ($H(X) \ge 3.65$) to catch Base32/Hex encoded covert data transfer.
* **TCP SYN Flood DoS**: Measures the half-open SYN-to-ACK ratio per destination socket ($\ge 4.0\text{x}$) to detect resource exhaustion attacks.
* **Network Reconnaissance**: Identifies vertical multi-port scans (Nmap/Masscan) and horizontal subnet IP sweeps.
* **TLS ClientHello SNI Extractor & JA3**: Extracts Server Name Indication (SNI) hostnames and computes MD5 JA3 fingerprint hashes.

---

## Quickstart & Testing

### 1. Clone & Setup
```bash
git clone https://github.com/Adityasingh230058/packet-hound.git
cd packet-hound
pip install -r requirements.txt
```

### 2. Generate Realistic Sample Capture
Generate a synthetic binary `.pcap` capture containing normal web traffic + active attack vectors:
```bash
python samples/generate_sample_pcap.py
```

### 3. Run the Dissector & Threat Engine
```bash
python src/main.py --pcap samples/network_traffic.pcap
```

### 4. Run Automated Unit Tests
```bash
pytest -v tests/
```

---

## Architecture
```text
packet-hound/
├── src/
│   ├── parser/               # Binary frame & protocol dissectors
│   │   ├── ethernet.py       # Ethernet II & 802.1Q VLAN
│   │   ├── arp.py            # ARP request/reply
│   │   ├── ip.py             # IPv4 & IPv6 headers
│   │   ├── transport.py      # TCP (flags/windows) & UDP
│   │   ├── dns.py            # DNS decoder & Shannon entropy
│   │   └── tls.py            # TLS ClientHello SNI & JA3 hash
│   ├── detectors/            # Network threat engines
│   │   ├── arp_spoof.py      # ARP cache poisoning detector
│   │   ├── syn_flood.py      # TCP SYN flood DoS detector
│   │   ├── dns_tunnel.py     # DNS data exfiltration detector
│   │   └── port_scan.py      # Vertical & horizontal scan detector
│   ├── flow/                 # 5-tuple bidirectional session tracker
│   │   └── reconstructor.py  # Session state & duration calculator
│   ├── pcap/                 # Pure-Python binary PCAP reader/writer
│   │   └── reader.py         # Struct-based PCAP parser
│   └── main.py               # CLI packet stream & summary table
├── samples/                  # Binary PCAP test captures & generators
├── tests/                    # 12 automated pytest unit tests
└── .github/workflows/        # Automated CI/CD testing workflow
```

---

## License

Distributed under the **MIT License**. See `LICENSE` for more information.

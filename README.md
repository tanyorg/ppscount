# ppscount

A lightweight CLI tool written in Rust to count and visualize inbound packets per second (PPS) in real-time or from PCAP files.

## Features
- Real-time inbound packet counting from live network interfaces
- Fast offline analysis from PCAP files (with optional real-time playback simulation)
- Flexible source IP filtering (exclude specific subnets using CIDR)
- Destination port filtering
- In-terminal ASCII bar chart representation

## Requirements
- Linux (uses `AF_PACKET` raw sockets for live capture)
- Root privileges (`sudo`) for live interface capture

## Supported Platforms

Tested and confirmed working on:

- Ubuntu 24.04.4 LTS

## Installation

```bash
cargo build --release
```
Binary will be generated at ./target/release/ppscount.

## Usage
Count inbound packets/sec from interface or pcap file with exclusion filter.

Usage: ppscount [OPTIONS]

Options:

| -i | --interface <INTERFACE> | Network interface to capture [default: eth0] |
| -f | --file <FILE> | Path to pcap file |
| -p | --port <PORT> | Target destination port |
| -o | --omit <OMIT>... | IP prefixes/addresses to exclude (e.g., -o 192.168.1.0/24) |
| -s | --scale <SCALE> | Packets per '*' character in bar chart [default: 100] |
| -r |  --realtime | Simulate real-time playback speed when reading pcap |
| -h | --help | Print help |
  -V,| --version | Print version |

## Examples

Live Capture:

```bash
sudo ./target/release/ppscount -i eth0 -p 80 -o 192.168.1.0/24
```

PCAP Playback:
```bash
./target/release/ppscount -f capture.pcap --realtime
```

## License

MIT

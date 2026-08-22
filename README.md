# ppscount

A lightweight CLI tool written in Rust to count and visualize inbound packets per second (PPS) in real-time or from PCAP files.

## Features
- Real-time inbound packet counting from live network interfaces
- Fast offline analysis from PCAP files (with optional real-time playback simulation)
- Flexible source IP filtering (exclude specific subnets using CIDR)
- Destination port filtering
- In-terminal ASCII bar chart representation

## Requirements
- For Linux: AF_PACKET (raw sockets) and optionally AF_XDP for high-performance capture
- For macOS / BSD: libpcap (system-provided on macOS)
- Root privileges (`sudo`) are typically required for live interface capture

## Supported Platforms

Tested and confirmed working on:

- Ubuntu 24.04.4 LTS
- macOS (live capture via libpcap)

## Installation

```bash
cargo build --release
```
This builds the standard AF_PACKET version. The binary will be generated at
`./target/release/ppscount`.

To include AF_XDP support on Linux, enable the feature explicitly. The
resulting binary can select AF_XDP with `--af-xdp`:

```bash
cargo build --release --features af-xdp
sudo ./target/release/ppscount --af-xdp -i eth0
```

## Usage
Count inbound packets/sec from interface or pcap file with exclusion filter.

Usage: ppscount [OPTIONS]

Options:

| Short | Long / Argument | Description |
| :--- | :--- | :--- |
| `-i` | `--interface <INTERFACE>` | Network interface to capture (Live mode) [default: eth0] |
| `-f` | `--file <FILE>` | Read from PCAP file instead of live capture |
| `-p` | `--port <PORT>` | Target L4 port to count (TCP/UDP) |
| | `--destination-only` | Match only the destination port |
| `-x` | `--exclude <OMIT>` | Exclude traffic from specified CIDR networks (can be repeated) |
| `-s` | `--scale <SCALE>` | Scale factor for asterisk visualization bar [default: 100] |
| `-r` | `--realtime` | Playback PCAP file in real-time speed |
| | `--af-xdp` | Enable AF_XDP driver mode (requires a build with `--features af-xdp`) |
| `-h` | `--help` | Print help |
| `-V` | `--version` | Print version |

## Examples

Live Capture:

```bash
sudo ./target/release/ppscount -i eth0 -p 80 -x 192.168.1.0/24
```

AF_XDP Live Capture (Linux, feature-enabled build):

```bash
sudo ./target/release/ppscount --af-xdp -i eth0
```

PCAP Playback:
```bash
./target/release/ppscount -f capture.pcap --realtime
```

## License

MIT

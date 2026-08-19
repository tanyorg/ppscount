use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Walk IPv6 extension headers to locate the L4 protocol and L4 header start offset.
pub fn parse_ipv6_l4(pkt_data: &[u8], mut offset: usize, mut next_hdr: u8) -> Option<(u8, usize)> {
    for _ in 0..10 {
        match next_hdr {
            6 | 17 => return Some((next_hdr, offset)), // TCP or UDP
            0 | 43 | 60 => {
                // Hop-by-Hop, Routing, Destination Options
                if pkt_data.len() < offset + 2 {
                    return None;
                }
                next_hdr = pkt_data[offset];
                let ext_len = (pkt_data[offset + 1] as usize + 1) * 8;
                offset += ext_len;
            }
            44 => {
                // Fragment
                if pkt_data.len() < offset + 8 {
                    return None;
                }
                next_hdr = pkt_data[offset];
                offset += 8;
            }
            51 => {
                // AH (Authentication Header)
                if pkt_data.len() < offset + 2 {
                    return None;
                }
                next_hdr = pkt_data[offset];
                let ext_len = (pkt_data[offset + 1] as usize + 2) * 4;
                offset += ext_len;
            }
            _ => return Some((next_hdr, offset)), // ESP (50) or other unparseable L4 payload
        }
        if offset > pkt_data.len() {
            return None;
        }
    }
    None
}

/// Inspect packet data across various link-layer encapsulation types and apply target filters.
pub fn is_target_packet(
    pkt_data: &[u8],
    link_offset: usize,
    target_port: Option<u16>,
    exclude_networks: &[IpNet],
) -> bool {
    if pkt_data.len() < link_offset {
        return false;
    }

    let mut offset = link_offset;
    let eth_proto: u16;

    match link_offset {
        0 => {
            // DLT_RAW / Raw IP (Directly starts with IPv4 or IPv6 header)
            if pkt_data.is_empty() {
                return false;
            }
            let version = (pkt_data[0] >> 4) & 0x0F;
            eth_proto = match version {
                4 => 0x0800,
                6 => 0x86DD,
                _ => return false,
            };
        }
        4 => {
            // DLT_NULL / Loopback (4-byte header containing AF family)
            if pkt_data.len() < 4 {
                return false;
            }
            let version = (pkt_data[4] >> 4) & 0x0F;
            eth_proto = match version {
                4 => 0x0800,
                6 => 0x86DD,
                _ => return false,
            };
        }
        16 => {
            // DLT_LINUX_SLL (Linux Cooked Capture v1)
            eth_proto = u16::from_be_bytes([pkt_data[14], pkt_data[15]]);
        }
        20 => {
            // DLT_LINUX_SLL2 (Linux Cooked Capture v2)
            eth_proto = u16::from_be_bytes([pkt_data[0], pkt_data[1]]);
        }
        _ => {
            // Default to Ethernet (link_offset == 14) or dynamic offsets (e.g. Radiotap)
            if pkt_data.len() < offset {
                return false;
            }
            if link_offset >= 14 {
                let proto = u16::from_be_bytes([pkt_data[offset - 2], pkt_data[offset - 1]]);
                if proto == 0x8100 || proto == 0x88A8 {
                    // 802.1Q / 802.1ad VLAN tagging
                    if pkt_data.len() < offset + 4 {
                        return false;
                    }
                    eth_proto = u16::from_be_bytes([pkt_data[offset + 2], pkt_data[offset + 3]]);
                    offset += 4;
                } else {
                    eth_proto = proto;
                }
            } else {
                // Fallback IP version check for custom offsets
                let version = (pkt_data[offset] >> 4) & 0x0F;
                eth_proto = match version {
                    4 => 0x0800,
                    6 => 0x86DD,
                    _ => return false,
                };
            }
        }
    }

    let src_ip: IpAddr;
    let protocol: u8;
    let l4_start: usize;

    if eth_proto == 0x0800 {
        // IPv4 Processing
        if pkt_data.len() < offset + 20 {
            return false;
        }
        let ihl = ((pkt_data[offset] & 0x0F) as usize) * 4;
        if ihl < 20 || pkt_data.len() < offset + ihl {
            return false;
        }
        protocol = pkt_data[offset + 9];
        src_ip = IpAddr::V4(Ipv4Addr::new(
            pkt_data[offset + 12],
            pkt_data[offset + 13],
            pkt_data[offset + 14],
            pkt_data[offset + 15],
        ));
        l4_start = offset + ihl;
    } else if eth_proto == 0x86DD {
        // IPv6 Processing
        if pkt_data.len() < offset + 40 {
            return false;
        }
        let next_hdr = pkt_data[offset + 6];
        let mut ip6_bytes = [0u8; 16];
        ip6_bytes.copy_from_slice(&pkt_data[offset + 8..offset + 24]);
        src_ip = IpAddr::V6(Ipv6Addr::from(ip6_bytes));

        if let Some((p, l4_pos)) = parse_ipv6_l4(pkt_data, offset + 40, next_hdr) {
            protocol = p;
            l4_start = l4_pos;
        } else {
            return false;
        }
    } else {
        return false;
    }

    // IP Exclusion Filter
    if !exclude_networks.is_empty() && exclude_networks.iter().any(|net| net.contains(&src_ip)) {
        return false;
    }

    // Destination / Source Port Filter (TCP / UDP)
    if let Some(t_port) = target_port {
        if protocol != 6 && protocol != 17 {
            return false;
        }
        if pkt_data.len() < l4_start + 4 {
            return false;
        }
        let src_port = u16::from_be_bytes([pkt_data[l4_start], pkt_data[l4_start + 1]]);
        let dst_port = u16::from_be_bytes([pkt_data[l4_start + 2], pkt_data[l4_start + 3]]);

        // Either src or dst port must match target_port
        if src_port != t_port && dst_port != t_port {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Helper function to build a dummy Ethernet + IPv4 + TCP packet
    fn create_dummy_ipv4_tcp_packet(src_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet Header (14 bytes)
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 Header (20 bytes)
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x28]);
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&[10, 0, 0, 1]);

        // TCP Header (20 bytes)
        pkt.extend_from_slice(&[0x04, 0xD2]);
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.push(0x50);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0x70, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);

        pkt
    }

    // Helper function to build a dummy Ethernet + IPv6 + TCP packet
    fn create_dummy_ipv6_tcp_packet(src_ip: [u8; 16], dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet Header (14 bytes)
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6

        // IPv6 Header (40 bytes)
        pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version 6
        pkt.extend_from_slice(&[0x00, 0x14]); // Payload length: 20 bytes
        pkt.push(6); // Next Header: TCP
        pkt.push(64); // Hop Limit
        pkt.extend_from_slice(&src_ip); // Src IPv6
        pkt.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // Dst IPv6

        // TCP Header (20 bytes)
        pkt.extend_from_slice(&[0x04, 0xD2]);
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.push(0x50);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0x70, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);

        pkt
    }

    #[test]
    fn test_valid_ipv4_packet_matching() {
        let pkt = create_dummy_ipv4_tcp_packet([192, 168, 1, 100], 80);
        assert!(is_target_packet(&pkt, 14, Some(80), &[]));
    }

    #[test]
    fn test_valid_ipv6_packet_matching() {
        let src_ip = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let pkt = create_dummy_ipv6_tcp_packet(src_ip, 443);
        assert!(is_target_packet(&pkt, 14, Some(443), &[]));
    }

    #[test]
    fn test_vlan_tagged_packet() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        pkt.extend_from_slice(&[0x81, 0x00]); // VLAN Tag (802.1Q)
        pkt.extend_from_slice(&[0x00, 0x0A]); // TCI (VLAN ID 10)

        let raw_eth = create_dummy_ipv4_tcp_packet([192, 168, 1, 100], 80);
        pkt.extend_from_slice(&raw_eth[12..]); // Append IPv4 EtherType + Payload

        assert!(is_target_packet(&pkt, 14, Some(80), &[]));
    }

    #[test]
    fn test_dlt_raw_ip() {
        let eth_pkt = create_dummy_ipv4_tcp_packet([10, 0, 0, 5], 80);
        let raw_ip_pkt = &eth_pkt[14..];
        assert!(is_target_packet(raw_ip_pkt, 0, Some(80), &[]));
    }

    #[test]
    fn test_dlt_null_loopback() {
        let mut pkt = vec![0x02, 0x00, 0x00, 0x00]; // 4-byte Loopback header
        let eth_pkt = create_dummy_ipv4_tcp_packet([127, 0, 0, 1], 80);
        pkt.extend_from_slice(&eth_pkt[14..]);

        assert!(is_target_packet(&pkt, 4, Some(80), &[]));
    }

    #[test]
    fn test_cidr_exclusion() {
        let pkt = create_dummy_ipv4_tcp_packet([192, 168, 1, 100], 80);
        let exclude_net = IpNet::from_str("192.168.1.0/24").unwrap();
        assert!(!is_target_packet(&pkt, 14, Some(80), &[exclude_net]));
    }

    #[test]
    fn test_truncated_packet_safety() {
        let short_pkt = vec![0x00, 0x11, 0x22, 0x33, 0x44];
        assert!(!is_target_packet(&short_pkt, 14, None, &[]));
    }
}

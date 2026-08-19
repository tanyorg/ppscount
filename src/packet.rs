use ipnet::IpNet;
use libc::PACKET_OUTGOING;
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
    let mut eth_proto: u16;

    if link_offset == 14 {
        eth_proto = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
        if eth_proto == 0x8100 {
            // 802.1Q VLAN
            if pkt_data.len() < 18 {
                return false;
            }
            eth_proto = u16::from_be_bytes([pkt_data[16], pkt_data[17]]);
            offset = 18;
        }
    } else if link_offset == 16 {
        // SLL v1
        let sll_pkttype = u16::from_be_bytes([pkt_data[0], pkt_data[1]]);
        if sll_pkttype == PACKET_OUTGOING as u16 {
            return false;
        }
        eth_proto = u16::from_be_bytes([pkt_data[14], pkt_data[15]]);
        offset = 16;
    } else {
        eth_proto = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
        offset = 14;
    }

    let src_ip: IpAddr;
    let protocol: u8;
    let l4_start: usize;

    if eth_proto == 0x0800 {
        // IPv4
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
        // IPv6
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

    // Destination Port Filter
    if let Some(t_port) = target_port {
        if protocol != 6 && protocol != 17 {
            return false;
        }
        if pkt_data.len() < l4_start + 4 {
            return false;
        }
        let dst_port = u16::from_be_bytes([pkt_data[l4_start + 2], pkt_data[l4_start + 3]]);
        if dst_port != t_port {
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
    fn create_dummy_tcp_packet(src_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::new();

        // 1. Ethernet Header (14 bytes)
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dst MAC
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // Src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4 (0x0800)

        // 2. IPv4 Header (20 bytes)
        pkt.push(0x45); // Version 4, IHL 5 (20 bytes)
        pkt.push(0x00); // TOS
        pkt.extend_from_slice(&[0x00, 0x28]); // Total Length: 40
        pkt.extend_from_slice(&[0x00, 0x01]); // Identification
        pkt.extend_from_slice(&[0x00, 0x00]); // Flags / Fragment Offset
        pkt.push(64); // TTL
        pkt.push(6); // Protocol: TCP (6)
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&src_ip); // Src IP
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Dst IP

        // 3. TCP Header (20 bytes)
        pkt.extend_from_slice(&[0x04, 0xD2]); // Src Port: 1234
        pkt.extend_from_slice(&dst_port.to_be_bytes()); // Dst Port
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq Number
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack Number
        pkt.push(0x50); // Data Offset: 5 (20 bytes)
        pkt.push(0x02); // Flags: SYN
        pkt.extend_from_slice(&[0x70, 0x00]); // Window Size
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // Urgent Pointer

        pkt
    }

    #[test]
    fn test_valid_packet_matching() {
        let pkt = create_dummy_tcp_packet([192, 168, 1, 100], 80);

        // Should match port 80
        assert!(is_target_packet(&pkt, 14, Some(80), &[]));
    }

    #[test]
    fn test_port_mismatch() {
        let pkt = create_dummy_tcp_packet([192, 168, 1, 100], 80);

        // Should fail if target port is 443
        assert!(!is_target_packet(&pkt, 14, Some(443), &[]));
    }

    #[test]
    fn test_cidr_exclusion() {
        let pkt = create_dummy_tcp_packet([192, 168, 1, 100], 80);
        let exclude_net = IpNet::from_str("192.168.1.0/24").unwrap();

        // Should be excluded if source IP matches the CIDR range
        assert!(!is_target_packet(&pkt, 14, Some(80), &[exclude_net]));

        // Should pass if source IP is outside the excluded CIDR range
        let other_net = IpNet::from_str("10.0.0.0/8").unwrap();
        assert!(is_target_packet(&pkt, 14, Some(80), &[other_net]));
    }

    #[test]
    fn test_truncated_packet_safety() {
        // Malformed 5-byte packet (should return false without crashing or out-of-bounds access)
        let short_pkt = vec![0x00, 0x11, 0x22, 0x33, 0x44];

        assert!(!is_target_packet(&short_pkt, 14, None, &[]));
    }
}

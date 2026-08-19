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

use chrono::{Local, TimeZone};
use ipnet::IpNet;
use libc::{
    bind, recvfrom, setsockopt, sockaddr, sockaddr_ll, socklen_t, AF_PACKET, ETH_P_ALL,
    PACKET_OUTGOING, SOCK_RAW, SOL_SOCKET, SO_RCVBUF, SO_RCVTIMEO,
};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::packet::is_target_packet;

fn print_line(sec: i64, count: usize, scale: usize) {
    let dt = Local.timestamp_opt(sec, 0).unwrap();
    let timestamp = dt.format("%Y/%m/%d %H:%M:%S");
    let bar = count
        .checked_div(scale)
        .map(|n| format!("  {}", "*".repeat(n)))
        .unwrap_or_default();

    println!("[{}] pps: {:<5}{}", timestamp, count, bar);
}

pub fn process_pcap(
    pcap_path: &PathBuf,
    target_port: Option<u16>,
    exclude_networks: &[IpNet],
    scale: usize,
    realtime: bool,
    running: Arc<AtomicBool>,
) {
    let mut file = File::open(pcap_path).unwrap_or_else(|e| {
        eprintln!("Error opening pcap file '{:?}': {}", pcap_path, e);
        process::exit(1);
    });

    let mut global_header = [0u8; 24];
    if file.read_exact(&mut global_header).is_err() {
        eprintln!("Error: Invalid pcap file (header too short).");
        process::exit(1);
    }

    let magic = &global_header[0..4];
    let is_big_endian = match magic {
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => true,
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0x2b, 0x1a] => false,
        _ => {
            eprintln!("Error: Unsupported pcap magic number or format.");
            process::exit(1);
        }
    };

    let read_u32 = |b: &[u8]| -> u32 {
        let arr = [b[0], b[1], b[2], b[3]];
        if is_big_endian {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        }
    };

    let network = read_u32(&global_header[20..24]);
    let link_offset = match network {
        1 => 14,
        113 => 16,
        _ => 14,
    };

    let mut first_pcap_time: Option<f64> = None;
    let mut first_wall_time: Option<Instant> = None;
    let mut current_sec: Option<i64> = None;
    let mut packet_count = 0;

    let mut header_buf = [0u8; 16];
    let mut pkt_buf = vec![0u8; 65535];

    while running.load(Ordering::SeqCst) {
        if file.read_exact(&mut header_buf).is_err() {
            break;
        }

        let ts_sec = read_u32(&header_buf[0..4]) as i64;
        let ts_usec = read_u32(&header_buf[4..8]) as f64;
        let incl_len = read_u32(&header_buf[8..12]) as usize;

        // Guard against corrupt/malformed pcap lengths
        if incl_len > 65535 {
            eprintln!("Error: Invalid packet length in pcap: {} bytes.", incl_len);
            break;
        }

        if pkt_buf.len() < incl_len {
            pkt_buf.resize(incl_len, 0);
        }

        if file.read_exact(&mut pkt_buf[..incl_len]).is_err() {
            break;
        }

        if is_target_packet(
            &pkt_buf[..incl_len],
            link_offset,
            target_port,
            exclude_networks,
        ) {
            let pkt_time = ts_sec as f64 + (ts_usec / 1_000_000.0);

            if first_pcap_time.is_none() {
                first_pcap_time = Some(pkt_time);
                first_wall_time = Some(Instant::now());
                current_sec = Some(ts_sec);
            }

            let mut cur = current_sec.unwrap();
            while ts_sec > cur {
                print_line(cur, packet_count, scale);

                if realtime {
                    let pcap_elapsed = (cur + 1) as f64 - first_pcap_time.unwrap();
                    let wall_elapsed = first_wall_time.unwrap().elapsed().as_secs_f64();
                    let sleep_time = pcap_elapsed - wall_elapsed;
                    if sleep_time > 0.0 {
                        thread::sleep(Duration::from_secs_f64(sleep_time));
                    }
                }

                packet_count = 0;
                cur += 1;
                current_sec = Some(cur);
            }

            packet_count += 1;
        }
    }

    if let Some(cur) = current_sec {
        print_line(cur, packet_count, scale);
    }
}

pub fn process_live(
    interface: &str,
    target_port: Option<u16>,
    exclude_networks: &[IpNet],
    scale: usize,
    running: Arc<AtomicBool>,
) {
    let if_name = std::ffi::CString::new(interface).unwrap();
    let if_index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
    if if_index == 0 {
        eprintln!("Error: Network interface '{}' not found.", interface);
        process::exit(1);
    }

    let fd = unsafe { libc::socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
    if fd < 0 {
        eprintln!("Error: Root privileges required. Please run with sudo.");
        process::exit(1);
    }

    // Set 4MB Socket Receive Buffer (Warn on failure)
    let rcvbuf: libc::c_int = 4 * 1024 * 1024;
    let res_buf = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&rcvbuf) as socklen_t,
        )
    };
    if res_buf < 0 {
        eprintln!(
            "Warning: Failed to set SO_RCVBUF socket option. Continuing with system default."
        );
    }

    // Set Socket Read Timeout (100ms) (Warn on failure)
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    let res_tout = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of_val(&timeout) as socklen_t,
        )
    };
    if res_tout < 0 {
        eprintln!("Warning: Failed to set SO_RCVTIMEO socket option.");
    }

    // Bind socket to specific interface
    let mut sll: sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = AF_PACKET as u16;
    sll.sll_ifindex = if_index as i32;
    sll.sll_protocol = (ETH_P_ALL as u16).to_be();

    let res = unsafe {
        bind(
            fd,
            &sll as *const _ as *const sockaddr,
            std::mem::size_of::<sockaddr_ll>() as socklen_t,
        )
    };
    if res < 0 {
        eprintln!("Error binding to interface '{}'.", interface);
        process::exit(1);
    }

    let mut buf = [0u8; 65535];
    let mut storage: sockaddr_ll = unsafe { std::mem::zeroed() };

    let mut packet_count = 0;
    let mut current_sec = Local::now().timestamp();

    while running.load(Ordering::SeqCst) {
        // Reset storage_len before every recvfrom call to prevent potential length truncation
        let mut storage_len = std::mem::size_of::<sockaddr_ll>() as socklen_t;

        let n = unsafe {
            recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut storage as *mut _ as *mut sockaddr,
                &mut storage_len,
            )
        };

        // Check current time AFTER recvfrom() returns
        let now_sec = Local::now().timestamp();

        while now_sec > current_sec {
            print_line(current_sec, packet_count, scale);
            packet_count = 0;
            current_sec += 1;
        }

        if n < 0 {
            continue;
        }

        if storage.sll_pkttype == PACKET_OUTGOING {
            continue;
        }

        let pkt_data = &buf[..n as usize];
        if is_target_packet(pkt_data, 14, target_port, exclude_networks) {
            packet_count += 1;
        }
    }
}

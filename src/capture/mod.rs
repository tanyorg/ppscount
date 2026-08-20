pub mod backend;
pub mod raw_socket;

#[cfg(target_os = "linux")]
pub mod af_xdp;

#[cfg(not(target_os = "linux"))]
pub mod pcap_backend;

use anyhow::{bail, Context, Result};
use chrono::{Local, TimeZone};
use ipnet::IpNet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::packet::is_target_packet;
use backend::PacketBackend;

fn print_line(sec: i64, count: usize, scale: usize) {
    let timestamp = match Local.timestamp_opt(sec, 0).single() {
        Some(dt) => dt.format("%Y/%m/%d %H:%M:%S").to_string(),
        None => format!("UnixTS:{}", sec),
    };

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
) -> Result<()> {
    let file = File::open(pcap_path)
        .with_context(|| format!("Failed to open pcap file '{:?}'", pcap_path))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);

    let mut global_header = [0u8; 24];
    reader
        .read_exact(&mut global_header)
        .context("Invalid pcap file: header too short")?;

    let magic = &global_header[0..4];
    let is_big_endian = match magic {
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => true,
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0x2b, 0x1a] => false,
        _ => bail!("Unsupported pcap magic number or invalid format"),
    };

    let read_u32 = |b: &[u8]| -> u32 {
        let arr = [b[0], b[1], b[2], b[3]];
        if is_big_endian {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        }
    };

    let read_u16 = |b: &[u8]| -> u16 {
        let arr = [b[0], b[1]];
        if is_big_endian {
            u16::from_be_bytes(arr)
        } else {
            u16::from_le_bytes(arr)
        }
    };

    let network = read_u32(&global_header[20..24]);

    let mut first_pcap_time: Option<f64> = None;
    let mut first_wall_time: Option<Instant> = None;
    let mut current_sec: Option<i64> = None;
    let mut packet_count = 0;

    let mut header_buf = [0u8; 16];
    let mut pkt_buf = vec![0u8; 65535];

    while running.load(Ordering::SeqCst) {
        if reader.read_exact(&mut header_buf).is_err() {
            break;
        }

        let ts_sec = read_u32(&header_buf[0..4]) as i64;
        let ts_usec = read_u32(&header_buf[4..8]) as f64;
        let incl_len = read_u32(&header_buf[8..12]) as usize;

        if incl_len > 65535 {
            eprintln!("Warning: Corrupt packet length ({}) skipped.", incl_len);
            break;
        }

        if pkt_buf.len() < incl_len {
            pkt_buf.resize(incl_len, 0);
        }

        if reader.read_exact(&mut pkt_buf[..incl_len]).is_err() {
            eprintln!("Warning: Unexpected EOF in packet payload, stopping.");
            break;
        }

        let link_offset = match network {
            0 => 4,
            1 => 14,
            12 | 101 => 0,
            113 => 16,
            276 => 20,
            127 => {
                if incl_len < 4 {
                    continue;
                }
                read_u16(&pkt_buf[2..4]) as usize
            }
            _ => 14,
        };

        let pkt_data = &pkt_buf[..incl_len];

        if is_target_packet(pkt_data, link_offset, target_port, exclude_networks) {
            let pkt_time = ts_sec as f64 + (ts_usec / 1_000_000.0);

            if first_pcap_time.is_none() {
                first_pcap_time = Some(pkt_time);
                first_wall_time = Some(Instant::now());
                current_sec = Some(ts_sec);
            }

            let cur = current_sec.unwrap_or(ts_sec);

            if ts_sec < cur {
                packet_count += 1;
                continue;
            }

            let mut step_sec = cur;
            while ts_sec > step_sec {
                print_line(step_sec, packet_count, scale);

                if realtime {
                    let pcap_elapsed = (step_sec + 1) as f64 - first_pcap_time.unwrap();
                    let wall_elapsed = first_wall_time.unwrap().elapsed().as_secs_f64();
                    let sleep_time = pcap_elapsed - wall_elapsed;
                    if sleep_time > 0.0 {
                        thread::sleep(Duration::from_secs_f64(sleep_time));
                    }
                }

                packet_count = 0;
                step_sec += 1;
                current_sec = Some(step_sec);
            }

            packet_count += 1;
        }
    }

    if let Some(cur) = current_sec {
        print_line(cur, packet_count, scale);
    }

    Ok(())
}

pub fn process_live(
    interface: &str,
    target_port: Option<u16>,
    exclude_networks: &[IpNet],
    scale: usize,
    _use_af_xdp: bool,
    running: Arc<AtomicBool>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if use_af_xdp {
            let mut backend = af_xdp::AfXdpBackend::new(interface)?;
            return run_live_loop(&mut backend, target_port, exclude_networks, scale, running);
        }

        let mut backend = raw_socket::RawSocketBackend::new(interface)?;
        run_live_loop(&mut backend, target_port, exclude_networks, scale, running)
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Use libpcap-based backend on non-Linux platforms (macOS, *BSD, etc.).
        // The pcap backend uses the same PacketBackend trait so the live loop can be reused.
        let mut backend = pcap_backend::PcapBackend::new(interface)?;
        run_live_loop(&mut backend, target_port, exclude_networks, scale, running)
    }
}

fn run_live_loop(
    backend: &mut dyn PacketBackend,
    target_port: Option<u16>,
    exclude_networks: &[IpNet],
    scale: usize,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let mut packet_count = 0;
    let mut current_sec = Local::now().timestamp();

    while running.load(Ordering::SeqCst) {
        let now_sec = Local::now().timestamp();

        while now_sec > current_sec {
            print_line(current_sec, packet_count, scale);
            packet_count = 0;
            current_sec += 1;
        }

        if let Some((pkt_data, link_offset)) = backend.next_packet()? {
            if is_target_packet(pkt_data, link_offset, target_port, exclude_networks) {
                packet_count += 1;
            }
        }
    }

    Ok(())
}

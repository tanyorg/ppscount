mod capture;
mod cli;
mod packet;

use anyhow::Result;
use capture::{process_live, process_pcap};
use clap::Parser;
use cli::Args;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() -> Result<()> {
    let args = Args::parse();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("\nStopped.");
        process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let port_str = match args.port {
        Some(p) => format!("Port: {}", p),
        None => "All Ports".to_string(),
    };

    if let Some(ref pcap_file) = args.file {
        println!(
            "ppscount: Analyzing pcap file '{:?}' ({})...",
            pcap_file, port_str
        );
        if !args.omit.is_empty() {
            let nets: Vec<String> = args.omit.iter().map(|n| n.to_string()).collect();
            println!("Excluding source networks: {}", nets.join(", "));
        }
        if args.scale > 0 {
            println!("Bar chart scale: 1 '*' = {} packets/sec", args.scale);
        } else {
            println!("Bar chart: Disabled");
        }
        println!("Press Ctrl+C to stop.\n");

        process_pcap(
            pcap_file,
            args.port,
            args.destination_only,
            &args.omit,
            args.scale,
            args.realtime,
            running,
        )?;
    } else {
        println!(
            "ppscount: Monitoring Inbound Packets/sec on {} ({})...",
            args.interface, port_str
        );
        if args.af_xdp {
            println!("Driver mode: AF_XDP (eBPF Generic/SKB Mode) [EXPERIMENTAL]");
            println!("Note: AF_XDP mode is currently in development and may not operate reliably depending on NIC driver / queue configuration.");
        } else if cfg!(target_os = "linux") {
            println!("Driver mode: Standard Socket (AF_PACKET)");
        } else {
            println!("Driver mode: Standard Socket (libpcap)");
        }
        if !args.omit.is_empty() {
            let nets: Vec<String> = args.omit.iter().map(|n| n.to_string()).collect();
            println!("Excluding source networks: {}", nets.join(", "));
        }
        if args.scale > 0 {
            println!("Bar chart scale: 1 '*' = {} packets/sec", args.scale);
        } else {
            println!("Bar chart: Disabled");
        }
        println!("Press Ctrl+C to stop.\n");

        process_live(
            &args.interface,
            args.port,
            args.destination_only,
            &args.omit,
            args.scale,
            args.af_xdp,
            running,
        )?;
    }

    Ok(())
}

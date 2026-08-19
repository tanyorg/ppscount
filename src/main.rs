mod capture;
mod cli;
mod packet;

use capture::{process_live, process_pcap};
use clap::Parser;
use cli::Args;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
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
            &args.omit,
            args.scale,
            args.realtime,
            running,
        );
    } else {
        println!(
            "ppscount: Monitoring Inbound Packets/sec on {} ({})...",
            args.interface, port_str
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

        process_live(&args.interface, args.port, &args.omit, args.scale, running);
    }
}

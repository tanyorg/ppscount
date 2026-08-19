use clap::Parser;
use ipnet::IpNet;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ppscount",
    author,
    version,
    about = "Count inbound packets/sec from interface or pcap file with exclusion filter."
)]
pub struct Args {
    #[arg(
        short,
        long,
        default_value = "eth0",
        help = "Network interface to capture"
    )]
    pub interface: String,

    #[arg(
        short,
        long,
        help = "Path to pcap file (if specified, reads from file instead of interface)"
    )]
    pub file: Option<PathBuf>,

    #[arg(short, long, help = "Target destination port (default: all ports)")]
    pub port: Option<u16>,

    #[arg(
        short = 'o',
        long = "omit",
        num_args = 1..,
        help = "IP prefixes/addresses to exclude (e.g., -o 192.168.111.0/24 2001:db8::/32)"
    )]
    pub omit: Vec<IpNet>,

    #[arg(
        short,
        long,
        default_value_t = 100,
        help = "Number of packets per '*' character in the bar chart (set 0 to disable)"
    )]
    pub scale: usize,

    #[arg(
        short,
        long,
        help = "Simulate real-time playback speed when reading from pcap file"
    )]
    pub realtime: bool,
}

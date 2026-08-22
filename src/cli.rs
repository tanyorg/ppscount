use clap::Parser;
use ipnet::IpNet;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ppscount",
    version,
    about = "High-performance packet per second counter"
)]
pub struct Args {
    /// Network interface to capture (Live mode)
    #[arg(short, long, default_value = "eth0")]
    pub interface: String,

    /// Read from PCAP file instead of live capture
    #[arg(short, long, value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Target L4 port to count (TCP/UDP)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Match only the destination port instead of the source or destination port
    #[arg(long)]
    pub destination_only: bool,

    /// Exclude traffic from specified CIDR networks (can be repeated)
    #[arg(short = 'x', long = "exclude")]
    pub omit: Vec<IpNet>,

    /// Scale factor for asterisk visualization bar
    #[arg(short, long, default_value_t = 100)]
    pub scale: usize,

    /// Playback PCAP file in real-time speed
    #[arg(short, long)]
    pub realtime: bool,

    /// Enable AF_XDP driver mode (EXPERIMENTAL: under development, may not capture all queues or run reliably)
    #[arg(long = "af-xdp")]
    pub af_xdp: bool,
}

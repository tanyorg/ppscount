use anyhow::{anyhow, Context, Result};
use pcap::{Active, Capture};

use crate::capture::backend::PacketBackend;

/// Live capture backend using libpcap (works on macOS and other non-Linux OSes).
pub struct PcapBackend {
    cap: Capture<Active>,
    link_offset: usize,
}

impl PcapBackend {
    pub fn new(interface: &str) -> Result<Self> {
        // Build a live capture on the requested interface.
        let builder = Capture::from_device(interface)
            .with_context(|| format!("Device not found: {}", interface))?;

        let cap = builder
            .promisc(true)
            .snaplen(65535)
            .timeout(1000) // milliseconds
            .open()
            .with_context(|| format!("Failed to open device {} for capture", interface))?;

        // Determine datalink type and derive link-layer header offset similar to pcap file handling.
        // get_datalink() returns a pcap::Linktype (tuple struct wrapping an integer).
        let dlt = cap.get_datalink();

        let link_offset = match dlt.0 {
            0 => 4,   // DLT_NULL / loopback (4-byte)
            1 => 14,  // DLT_EN10MB (Ethernet)
            12 | 101 => 0, // DLT_RAW or other raw IP
            113 => 16, // DLT_LINUX_SLL (Cooked Capture) v1
            276 => 20, // DLT_LINUX_SLL2 (Cooked Capture v2)
            // Default to Ethernet offset which is common on macOS (en0, etc.)
            _ => 14,
        };

        Ok(Self { cap, link_offset })
    }
}

impl PacketBackend for PcapBackend {
    fn next_packet(&mut self) -> Result<Option<(&[u8], usize)>> {
        match self.cap.next_packet() {
            Ok(pkt) => Ok(Some((pkt.data, self.link_offset))),
            Err(e) => {
                let s = e.to_string();
                // Treat common non-fatal pcap conditions (like timeouts) as "no packet ready".
                if s.to_lowercase().contains("timeout") || s.contains("Timeout expired") || s.contains("No packets") {
                    Ok(None)
                } else {
                    Err(anyhow!(s))
                }
            }
        }
    }
}

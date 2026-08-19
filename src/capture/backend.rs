use anyhow::Result;

/// Abstract trait for packet capture backends.
pub trait PacketBackend {
    /// Receive the next raw packet byte slice along with its link-layer offset.
    /// Returns Ok(None) on timeout or when no packet is ready.
    fn next_packet(&mut self) -> Result<Option<(&[u8], usize)>>;
}

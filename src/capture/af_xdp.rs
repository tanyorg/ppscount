#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use xsk_rs::{
    config::{BindFlags, QueueSize, SocketConfig, UmemConfig, XdpFlags},
    CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem,
};

#[cfg(target_os = "linux")]
use super::backend::PacketBackend;

const BATCH_SIZE: usize = 64;
const FRAME_SIZE: usize = 4096;

#[cfg(target_os = "linux")]
pub struct AfXdpBackend {
    umem: Umem,
    _tx_queue: TxQueue,
    fill_queue: FillQueue,
    _comp_queue: CompQueue,
    rx_queue: RxQueue,
    frame_descs: Vec<FrameDesc>,
    rx_batch: Vec<FrameDesc>,
    rx_idx: usize,
    rx_count: usize,
    recycle_buf: Vec<FrameDesc>,
}

#[cfg(target_os = "linux")]
impl AfXdpBackend {
    pub fn new(interface: &str) -> Result<Self> {
        let queue_size = QueueSize::new(4096).context("Invalid queue size")?;
        let num_frames = NonZeroU32::new(4096).context("Invalid frame count")?;

        let umem_config = UmemConfig::builder()
            .fill_queue_size(queue_size)
            .comp_queue_size(queue_size)
            .build()
            .context("Failed to build UmemConfig")?;

        let socket_config = SocketConfig::builder()
            .rx_queue_size(queue_size)
            .tx_queue_size(queue_size)
            .xdp_flags(XdpFlags::XDP_FLAGS_SKB_MODE)
            .bind_flags(BindFlags::XDP_COPY)
            .build();

        // 1. Allocate UMEM shared memory region
        let (umem, frame_descs) = Umem::new(umem_config, num_frames, false)
            .context("Failed to allocate AF_XDP UMEM buffer")?;

        // 2. Bind AF_XDP socket to queue 0
        let dev_name = interface
            .parse()
            .with_context(|| format!("Invalid network interface name: '{}'", interface))?;
        let queue_id = 0u32;

        let (tx_queue, rx_queue, fq_cq) = unsafe {
            Socket::new(socket_config, &umem, &dev_name, queue_id)
        }
        .context(
            "Failed to bind AF_XDP socket. Root privileges (sudo) and XDP support required.",
        )?;

        let (mut fill_queue, comp_queue) =
            fq_cq.context("Failed to initialize AF_XDP Fill/Completion queues")?;

        // Populate RX Fill Queue with all initial frames
        let mut produced = 0;
        while produced < frame_descs.len() {
            let n = unsafe { fill_queue.produce(&frame_descs[produced..]) };
            if n == 0 {
                break;
            }
            produced += n;
        }

        Ok(Self {
            umem,
            _tx_queue: tx_queue,
            fill_queue,
            _comp_queue: comp_queue,
            rx_queue,
            frame_descs,
            rx_batch: vec![FrameDesc::default(); BATCH_SIZE],
            rx_idx: 0,
            rx_count: 0,
            recycle_buf: Vec::with_capacity(4096),
        })
    }

    fn flush_fill_queue(&mut self) {
        if self.recycle_buf.is_empty() {
            return;
        }
        let n = unsafe { self.fill_queue.produce(&self.recycle_buf) };
        if n > 0 {
            self.recycle_buf.drain(0..n);
        }
    }
}

#[cfg(target_os = "linux")]
impl PacketBackend for AfXdpBackend {
    fn next_packet(&mut self) -> Result<Option<(&[u8], usize)>> {
        loop {
            // 1. Flush recycled frame descriptors to kernel Fill Queue
            self.flush_fill_queue();

            // 2. Return packet if current batch has unconsumed descriptors
            if self.rx_idx < self.rx_count {
                let desc = self.rx_batch[self.rx_idx];
                self.rx_idx += 1;

                let pkt_data = unsafe { self.umem.data(&desc) };
                let pkt_slice = unsafe {
                    std::slice::from_raw_parts(pkt_data.as_ref().as_ptr(), pkt_data.as_ref().len())
                };

                // Retrieve pristine FrameDesc from original vector using frame index
                let frame_idx = desc.addr() / FRAME_SIZE;
                if let Some(&pristine_desc) = self.frame_descs.get(frame_idx) {
                    self.recycle_buf.push(pristine_desc);
                }

                let link_offset = 14; // Ethernet header offset
                return Ok(Some((pkt_slice, link_offset)));
            }

            // 3. Batch exhausted: attempt to consume next batch from RX queue
            self.rx_idx = 0;
            self.rx_count = 0;

            let rcvd = unsafe { self.rx_queue.consume(&mut self.rx_batch) };
            if rcvd > 0 {
                self.rx_count = rcvd;
                continue;
            }

            // 4. Ensure Fill Queue is flushed BEFORE calling poll()
            self.flush_fill_queue();

            // 5. Poll kernel socket to trigger SKB driver processing
            if self.rx_queue.poll(10)? {
                let rcvd = unsafe { self.rx_queue.consume(&mut self.rx_batch) };
                if rcvd > 0 {
                    self.rx_count = rcvd;
                    continue;
                }
            }

            return Ok(None);
        }
    }
}

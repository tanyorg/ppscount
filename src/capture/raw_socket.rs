#[cfg(target_os = "linux")]
use anyhow::{bail, Context, Result};
#[cfg(target_os = "linux")]
use libc::{
    bind, recvfrom, setsockopt, sockaddr, sockaddr_ll, socklen_t, AF_PACKET, ETH_P_ALL,
    PACKET_OUTGOING, SOCK_RAW, SOL_SOCKET, SO_RCVBUF, SO_RCVTIMEO,
};

#[cfg(target_os = "linux")]
use super::backend::PacketBackend;

#[cfg(target_os = "linux")]
pub struct RawSocketBackend {
    fd: i32,
    buf: [u8; 65535],
    storage: sockaddr_ll,
}

#[cfg(target_os = "linux")]
impl RawSocketBackend {
    pub fn new(interface: &str) -> Result<Self> {
        let if_name = std::ffi::CString::new(interface)
            .context("Invalid interface name (contains null byte)")?;
        // SAFETY: `if_name` is a valid NUL-terminated interface name and is
        // alive for the duration of the call.
        let if_index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
        if if_index == 0 {
            bail!("Network interface '{}' not found", interface);
        }

        // SAFETY: the arguments are valid constants and no Rust references
        // are exposed through the returned file descriptor.
        let fd = unsafe { libc::socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
        if fd < 0 {
            bail!("Failed to create raw socket. Root privileges (sudo) required");
        }

        let rcvbuf: libc::c_int = 4 * 1024 * 1024;
        // SAFETY: `rcvbuf` is a valid pointer to a value of the size passed to
        // setsockopt, and `fd` is a valid socket descriptor.
        unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVBUF,
                &rcvbuf as *const _ as *const libc::c_void,
                std::mem::size_of_val(&rcvbuf) as socklen_t,
            );
        }

        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        // SAFETY: `timeout` is a valid timeval with the matching size, and
        // `fd` is a valid socket descriptor.
        unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of_val(&timeout) as socklen_t,
            );
        }

        // SAFETY: zero is a valid initial byte representation for sockaddr_ll;
        // all fields used below are initialized before bind.
        let mut sll: sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = AF_PACKET as u16;
        sll.sll_ifindex = if_index as i32;
        sll.sll_protocol = (ETH_P_ALL as u16).to_be();

        // SAFETY: `sll` is initialized as an AF_PACKET sockaddr and the
        // pointer and length describe that exact value.
        let res = unsafe {
            bind(
                fd,
                &sll as *const _ as *const sockaddr,
                std::mem::size_of::<sockaddr_ll>() as socklen_t,
            )
        };
        if res < 0 {
            bail!("Error binding raw socket to interface '{}'", interface);
        }

        Ok(Self {
            fd,
            buf: [0u8; 65535],
            // SAFETY: zero is a valid initial byte representation for the
            // address storage populated by recvfrom.
            storage: unsafe { std::mem::zeroed() },
        })
    }
}

#[cfg(target_os = "linux")]
impl PacketBackend for RawSocketBackend {
    fn next_packet(&mut self) -> Result<Option<(&[u8], usize)>> {
        let mut storage_len = std::mem::size_of::<sockaddr_ll>() as socklen_t;

        // SAFETY: `self.fd` is owned by this backend and the descriptor is
        // closed at most once.
        let n = unsafe {
            recvfrom(
                self.fd,
                self.buf.as_mut_ptr() as *mut libc::c_void,
                self.buf.len(),
                0,
                &mut self.storage as *mut _ as *mut sockaddr,
                &mut storage_len,
            )
        };

        if n < 0 {
            return Ok(None); // Timeout or signal interrupted
        }

        if self.storage.sll_pkttype == PACKET_OUTGOING as u8 {
            return Ok(None);
        }

        let link_offset = 14; // Standard Ethernet header length
        Ok(Some((&self.buf[..n as usize], link_offset)))
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawSocketBackend {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: `self.fd` is owned by this backend and is closed only
            // during Drop.
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

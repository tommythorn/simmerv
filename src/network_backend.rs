/// Packet I/O interface between a `VirtIO` net device and the host network.
pub trait NetworkBackend: Send {
    /// Send an ethernet frame to the host.
    fn send(&mut self, packet: &[u8]);
    /// Receive an ethernet frame from the host, or `None` if none is
    /// immediately available (non-blocking).
    fn recv(&mut self) -> Option<Vec<u8>>;
    /// Whether a real link is present.  Returns `false` for the dummy backend
    /// so the guest sees `LINK_DOWN` and does not attempt to transmit.
    fn is_connected(&self) -> bool { true }
}

/// Null backend: drops all TX frames, never produces RX frames.
pub struct DummyNetworkBackend;

impl NetworkBackend for DummyNetworkBackend {
    fn send(&mut self, _packet: &[u8]) {}
    fn recv(&mut self) -> Option<Vec<u8>> { None }
    fn is_connected(&self) -> bool { false }
}

/// Linux TAP (layer-2) backend.
///
/// Opens `/dev/net/tun` and creates (or attaches to) the interface named by
/// `TapBackend::open`.  The process must have `CAP_NET_ADMIN` or run as root.
#[cfg(target_os = "linux")]
pub use tap::TapBackend;

#[cfg(target_os = "linux")]
mod tap {
    use super::NetworkBackend;
    use std::io::Read;
    use std::io::Write;
    use std::io::{self};

    // _IOW('T', 202, int) on Linux x86/ARM/RISC-V
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

    pub struct TapBackend {
        file: std::fs::File,
    }

    impl TapBackend {
        /// Open or create a TAP interface named `name`.
        ///
        /// # Errors
        /// Returns an error if `/dev/net/tun` cannot be opened or the
        /// `TUNSETIFF` ioctl fails.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        pub fn open(name: &str) -> io::Result<Self> {
            use std::os::unix::io::AsRawFd;

            #[repr(C)]
            struct Ifreq {
                ifr_name: [libc::c_char; 16],
                ifr_flags: i16,
                _pad: [u8; 22],
            }

            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/net/tun")?;

            let mut ifr = Ifreq {
                ifr_name: [0; 16],
                ifr_flags: (libc::IFF_TAP | libc::IFF_NO_PI) as i16,
                _pad: [0; 22],
            };
            for (i, &b) in name.as_bytes().iter().take(15).enumerate() {
                ifr.ifr_name[i] = b as libc::c_char;
            }

            unsafe {
                if libc::ioctl(file.as_raw_fd(), TUNSETIFF, &ifr) < 0 {
                    return Err(io::Error::last_os_error());
                }
                let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
                libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            Ok(Self { file })
        }
    }

    impl NetworkBackend for TapBackend {
        fn send(&mut self, packet: &[u8]) { let _ = self.file.write_all(packet); }

        fn recv(&mut self) -> Option<Vec<u8>> {
            let mut buf = vec![0u8; 1518];
            match self.file.read(&mut buf) {
                Ok(n) if n > 0 => {
                    buf.truncate(n);
                    Some(buf)
                }
                _ => None,
            }
        }
    }
}

/// macOS vmnet (layer-2, NAT/shared) backend.
///
/// Uses Apple's `vmnet.framework` to provide ethernet-level packet I/O.
/// Requires root or the `com.apple.vm.networking` entitlement.
#[cfg(target_os = "macos")]
pub use vmnet::VmnetBackend;

#[cfg(target_os = "macos")]
mod vmnet {
    use super::NetworkBackend;
    use std::io;

    enum VmnetHandleOpaque {}

    unsafe extern "C" {
        fn simmerv_vmnet_open() -> *mut VmnetHandleOpaque;
        fn simmerv_vmnet_read(
            h: *mut VmnetHandleOpaque,
            buf: *mut u8,
            cap: libc::c_int,
        ) -> libc::c_int;
        fn simmerv_vmnet_write(
            h: *mut VmnetHandleOpaque,
            buf: *const u8,
            len: libc::c_int,
        ) -> libc::c_int;
        fn simmerv_vmnet_close(h: *mut VmnetHandleOpaque);
    }

    pub struct VmnetBackend {
        handle: *mut VmnetHandleOpaque,
        buf: Vec<u8>,
    }

    // SAFETY: VmnetBackend is only used from one thread at a time.
    unsafe impl Send for VmnetBackend {}

    impl VmnetBackend {
        /// Open vmnet in shared (NAT) mode.
        ///
        /// # Errors
        /// Returns an error if `vmnet_start_interface` fails (usually
        /// insufficient privileges).
        pub fn open() -> io::Result<Self> {
            let handle = unsafe { simmerv_vmnet_open() };
            if handle.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "vmnet_start_interface failed — try running as root",
                ));
            }
            Ok(Self {
                handle,
                buf: vec![0u8; 4096],
            })
        }
    }

    impl Drop for VmnetBackend {
        fn drop(&mut self) { unsafe { simmerv_vmnet_close(self.handle) }; }
    }

    impl NetworkBackend for VmnetBackend {
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        fn send(&mut self, packet: &[u8]) {
            unsafe {
                simmerv_vmnet_write(self.handle, packet.as_ptr(), packet.len() as libc::c_int);
            }
        }

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            clippy::cast_sign_loss
        )]
        fn recv(&mut self) -> Option<Vec<u8>> {
            let n = unsafe {
                simmerv_vmnet_read(
                    self.handle,
                    self.buf.as_mut_ptr(),
                    self.buf.len() as libc::c_int,
                )
            };
            if n > 0 {
                Some(self.buf[..n as usize].to_vec())
            } else {
                None
            }
        }
    }
}

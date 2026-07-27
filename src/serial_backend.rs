/// The I/O interface between a UART device and the host environment.
///
/// Device side: `put_byte` / `get_input`.
/// Host side:   `put_input` / `get_output` (used by WASM host, test harnesses,
/// etc.)
pub trait SerialBackend {
    /// Send a byte from the emulated device to the host (e.g. display it).
    fn put_byte(&mut self, value: u8);
    /// Poll a byte from the host into the emulated device. Returns 0 if none.
    fn get_input(&mut self) -> u8;
    /// Drain host input and process host-side control keys, buffering any
    /// guest-bound bytes for `get_input`. Called every device service tick even
    /// when the device's receive FIFO is full, so host control keys (e.g. the
    /// Ctrl-C menu) keep working while the guest is not reading. Default no-op
    /// for backends with no host-side control keys.
    fn poll_input(&mut self) {}
    /// (Host-side) inject a byte into the device's receive buffer.
    fn put_input(&mut self, data: u8);
    /// (Host-side) drain a byte from the device's transmit buffer. Returns 0 if
    /// empty.
    fn get_output(&mut self) -> u8;
}

/// Null backend: discards output, returns no input.  Used in tests.
pub struct DummySerialBackend {}

impl Default for DummySerialBackend {
    fn default() -> Self { Self::new() }
}

impl DummySerialBackend {
    #[must_use]
    pub const fn new() -> Self { Self {} }
}

impl SerialBackend for DummySerialBackend {
    fn put_byte(&mut self, _value: u8) {}
    fn get_input(&mut self) -> u8 { 0 }
    fn put_input(&mut self, _value: u8) {}
    fn get_output(&mut self) -> u8 { 0 }
}

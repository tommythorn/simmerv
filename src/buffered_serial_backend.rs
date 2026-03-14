use crate::serial_backend::SerialBackend;

/// Buffered `SerialBackend` — used by the WASM host which drives both sides.
pub struct BufferedSerialBackend {
    input_data: Vec<u8>,
    output_data: Vec<u8>,
}

impl Default for BufferedSerialBackend {
    fn default() -> Self { Self::new() }
}

impl BufferedSerialBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            input_data: vec![],
            output_data: vec![],
        }
    }
}

impl SerialBackend for BufferedSerialBackend {
    fn put_byte(&mut self, value: u8) { self.output_data.push(value); }
    fn get_input(&mut self) -> u8 {
        if self.input_data.is_empty() {
            0
        } else {
            self.input_data.remove(0)
        }
    }
    fn put_input(&mut self, value: u8) { self.input_data.push(value); }
    fn get_output(&mut self) -> u8 {
        if self.output_data.is_empty() {
            0
        } else {
            self.output_data.remove(0)
        }
    }
}

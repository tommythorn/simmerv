use std::io::Write;
use std::io::stdout;
use std::str;

use simmerv::serial_backend::SerialBackend;

/// Dummy `Terminal`. Output will be displayed in command line
/// and input will not be handled.
pub struct DummyTerminal {}

impl DummyTerminal {
    pub const fn new() -> Self { Self {} }
}

impl SerialBackend for DummyTerminal {
    fn put_byte(&mut self, value: u8) {
        let str = vec![value];
        match str::from_utf8(&str) {
            Ok(s) => {
                print!("{s}");
            }
            Err(_e) => {}
        }
        let _ = stdout().flush();
    }

    fn get_input(&mut self) -> u8 { 0 }

    // Wasm specific methods. No use.

    fn put_input(&mut self, _value: u8) {}

    fn get_output(&mut self) -> u8 { 0 }
}

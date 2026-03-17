use crate::nonblocknoecho::NonblockNoEcho;
use simmerv::serial_backend::SerialBackend;
use std::io::Stdout;
use std::io::Write;
use std::io::{self};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Popup `Terminal` used for desktop program.
pub struct PopupTerminal {
    input: NonblockNoEcho,
}

impl PopupTerminal {
    pub fn new(
        ctrlc_breaks: bool,
        exit_flag: Arc<AtomicBool>,
        snapshot_flag: Arc<AtomicBool>,
        verbose_flag: Arc<AtomicBool>,
        speedometer_flag: Arc<AtomicBool>,
        tracing_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            input: NonblockNoEcho::new(
                ctrlc_breaks,
                exit_flag,
                snapshot_flag,
                verbose_flag,
                speedometer_flag,
                tracing_flag,
            ),
        }
    }
}

impl SerialBackend for PopupTerminal {
    fn put_byte(&mut self, value: u8) {
        let stdout: Stdout = io::stdout();
        loop {
            if stdout.lock().flush().is_ok() {
                break;
            }
        }
        print!("{}", value as char);
    }

    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn get_input(&mut self) -> u8 {
        let stdout: Stdout = io::stdout();
        loop {
            if stdout.lock().flush().is_ok() {
                break;
            }
        }
        self.input.get_key().unwrap_or_default()
    }

    // Wasm specific methods. No use.
    fn put_input(&mut self, _value: u8) {}

    fn get_output(&mut self) -> u8 { 0 }
}

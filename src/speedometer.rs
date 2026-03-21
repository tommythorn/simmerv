use std::io::{self};
use wasm_timer::Instant;

#[cfg(not(target_arch = "wasm32"))]
use std::io::Write;

#[cfg(target_os = "macos")]
const TIOCGWINSZ: libc::c_ulong = 0x40087468;

#[cfg(target_os = "linux")]
const TIOCGWINSZ: libc::c_ulong = 0x5413;

/// Speedometer for tracking and displaying event rates
#[allow(dead_code)]
pub struct Speedometer {
    pub last_time: Instant,
    last_count: u64,
    first_time: Instant,
}

impl Speedometer {
    /// Create a new speedometer
    #[must_use]
    pub fn new() -> Self {
        let first_time = Instant::now();
        Self {
            last_count: 0,
            first_time,
            last_time: first_time,
        }
    }

    /// Update the display with current event count
    /// # Errors
    /// Can't access the terminal
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    #[allow(clippy::cast_precision_loss)]
    pub fn update(&mut self, current_count: u64) -> io::Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let width = get_terminal_width()?;

            let current_time = Instant::now();

            let elapsed = current_time.duration_since(self.first_time).as_secs_f64();

            let rate_per_sec = if elapsed > 0.0 {
                current_count as f64 / elapsed
            } else {
                0.0
            };

            let rate_str = format!("{:.2} Mi/s", rate_per_sec / 1_000_000.0);

            self.last_count = current_count;
            self.last_time = current_time;

            #[allow(clippy::cast_possible_truncation)]
            let rate_len = rate_str.len() as u16;
            let col_position = width.saturating_sub(rate_len);

            let mut stdout = io::stdout();
            write!(stdout, "\x1b[s")?;
            write!(stdout, "\x1b[1;{}H", col_position + 1)?;
            write!(stdout, "{rate_str}")?;
            write!(stdout, "\x1b[u")?;
            stdout.flush()?;
        }

        Ok(())
    }
}

impl Default for Speedometer {
    fn default() -> Self { Self::new() }
}

/// Get the current terminal width using TIOCGWINSZ ioctl
#[cfg(not(target_arch = "wasm32"))]
fn get_terminal_width() -> io::Result<u16> {
    #[repr(C)]
    struct Winsize {
        row: u16,
        col: u16,
        xpixel: u16,
        ypixel: u16,
    }

    let mut size = Winsize {
        row: 0,
        col: 0,
        xpixel: 0,
        ypixel: 0,
    };

    unsafe {
        if libc::ioctl(libc::STDOUT_FILENO, TIOCGWINSZ, &mut size) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(size.col)
}

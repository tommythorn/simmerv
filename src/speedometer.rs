use std::io::{self};
use wasm_timer::Instant;

use crate::mmu::TlbDisplayStats;
use crate::uop_cache::UopCacheStats;

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
    prev_stats: TlbDisplayStats,
    prev_cache: UopCacheStats,
    prev_line_widths: Vec<u16>,
}

impl Speedometer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_count: 0,
            last_time: Instant::now(),
            prev_stats: TlbDisplayStats::default(),
            prev_cache: UopCacheStats::default(),
            prev_line_widths: Vec::new(),
        }
    }

    /// Update the display with current event count and TLB statistics.
    /// # Errors
    /// Can't access the terminal
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    #[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
    pub fn update(
        &mut self,
        current_count: u64,
        stats: TlbDisplayStats,
        cache: UopCacheStats,
    ) -> io::Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let width = get_terminal_width()?;
            let current_time = Instant::now();
            let elapsed = current_time.duration_since(self.last_time).as_secs_f64();
            let delta_count = current_count - self.last_count;

            let rate_per_sec = if elapsed > 0.0 {
                delta_count as f64 / elapsed
            } else {
                0.0
            };

            let mi = delta_count as f64 / 1_000_000.0;

            // Build lines: Mi/s always shown, TLB counters only if non-zero
            let mut lines: Vec<String> = Vec::new();
            lines.push(format!("{:.2} Mi/s", rate_per_sec / 1_000_000.0));

            if mi > 0.0 {
                let d = |cur: u64, prev: u64| (cur - prev) as f64 / mi;

                let imiss = d(stats.itlb_misses, self.prev_stats.itlb_misses);
                let dmiss = d(stats.dtlb_misses, self.prev_stats.dtlb_misses);
                let mut miss_parts: Vec<String> = Vec::new();
                if imiss > 0.0 {
                    miss_parts.push(format!("iTLB {imiss:.0}/Mi"));
                }
                if dmiss > 0.0 {
                    miss_parts.push(format!("dTLB {dmiss:.0}/Mi"));
                }
                if !miss_parts.is_empty() {
                    lines.push(format!("miss {}", miss_parts.join("  ")));
                }

                let flush_full = d(stats.flush_full, self.prev_stats.flush_full);
                let flush_asid = d(stats.flush_asid, self.prev_stats.flush_asid);
                let flush_vpage = d(stats.flush_vpage, self.prev_stats.flush_vpage);
                let flush_vpage_asid = d(stats.flush_vpage_asid, self.prev_stats.flush_vpage_asid);
                let mut flush_parts: Vec<String> = Vec::new();
                if flush_full > 0.0 {
                    flush_parts.push(format!("full {flush_full:.0}/Mi"));
                }
                if flush_asid > 0.0 {
                    flush_parts.push(format!("asid {flush_asid:.0}/Mi"));
                }
                if flush_vpage > 0.0 {
                    flush_parts.push(format!("vpage {flush_vpage:.0}/Mi"));
                }
                if flush_vpage_asid > 0.0 {
                    flush_parts.push(format!("vp+asid {flush_vpage_asid:.0}/Mi"));
                }
                if !flush_parts.is_empty() {
                    lines.push(format!("flush {}", flush_parts.join("  ")));
                }

                let cache_misses = d(cache.misses, self.prev_cache.misses);
                let cache_flushes = d(cache.flushes, self.prev_cache.flushes);
                let mut cache_parts: Vec<String> = Vec::new();
                if cache_misses > 0.0 {
                    cache_parts.push(format!("miss {cache_misses:.0}/Mi"));
                }
                if cache_flushes > 0.0 {
                    cache_parts.push(format!("flush {cache_flushes:.0}/Mi"));
                }
                if !cache_parts.is_empty() {
                    lines.push(format!("uop$ {}", cache_parts.join("  ")));
                }
            }

            self.last_count = current_count;
            self.last_time = current_time;
            self.prev_stats = stats;
            self.prev_cache = cache;

            let mut stdout = io::stdout();
            write!(stdout, "\x1b[s")?;
            let mut new_widths = Vec::with_capacity(lines.len());
            let prev = &self.prev_line_widths;
            let n_rows = lines.len().max(prev.len());
            for row in 0..n_rows {
                if let Some(line) = lines.get(row) {
                    #[allow(clippy::cast_possible_truncation)]
                    let line_len = line.len() as u16;
                    let pad = prev.get(row).copied().unwrap_or(0).saturating_sub(line_len);
                    let total = line_len + pad;
                    let col = width.saturating_sub(total) + 1;
                    write!(
                        stdout,
                        "\x1b[{};{col}H{line}{:pad$}",
                        row + 1,
                        "",
                        pad = pad as usize
                    )?;
                    new_widths.push(total);
                } else {
                    // Previous update had a line here but now it's gone — blank it
                    let prev_w = prev[row];
                    let col = width.saturating_sub(prev_w) + 1;
                    write!(
                        stdout,
                        "\x1b[{};{col}H{:w$}",
                        row + 1,
                        "",
                        w = prev_w as usize
                    )?;
                }
            }
            self.prev_line_widths = new_widths;
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

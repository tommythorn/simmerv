use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

pub struct NonblockNoEcho {
    stdin: i32,
    orig_termios: termios::Termios,
    /// Guest-bound bytes already drained from the host fd (Ctrl-C / menu keys
    /// removed). Buffered here so nothing is stranded when the device's receive
    /// FIFO is momentarily full.
    pending: VecDeque<u8>,
    exit_flag: Arc<AtomicBool>,
    snapshot_flag: Arc<AtomicBool>,
    verbose_flag: Arc<AtomicBool>,
    speedometer_flag: Arc<AtomicBool>,
    pub tracing_flag: Arc<AtomicBool>,
    awaiting_command: bool,
}

impl NonblockNoEcho {
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    pub fn new(
        ctrlc_breaks: bool,
        exit_flag: Arc<AtomicBool>,
        snapshot_flag: Arc<AtomicBool>,
        verbose_flag: Arc<AtomicBool>,
        speedometer_flag: Arc<AtomicBool>,
        tracing_flag: Arc<AtomicBool>,
    ) -> Self {
        use std::os::unix::io::AsRawFd;
        use termios::ECHO;
        use termios::ICANON;
        use termios::ISIG;
        use termios::TCSANOW;
        use termios::Termios;
        use termios::tcsetattr;

        let stdin: i32 = std::io::stdin().as_raw_fd();
        assert_eq!(stdin, 0);

        // Do NOT set O_NONBLOCK on stdin: on macOS stdin and stdout share the
        // same open file description (the controlling terminal), so setting
        // O_NONBLOCK would also make stdout non-blocking, causing println! to
        // panic with EAGAIN under tracing load.  Instead we use poll(2) with a
        // zero timeout to check readability before each read.

        let orig_termios = Termios::from_fd(stdin).expect("Termio::from_fd(stdin)");

        let mut termios = orig_termios;
        termios.c_lflag &= !(ECHO | ICANON); // no echo and canonical mode
        if !ctrlc_breaks {
            termios.c_lflag &= !ISIG; // Don't break on Ctrl-C
        }

        termios.c_iflag &= !(termios::IGNBRK
            | termios::BRKINT
            | termios::PARMRK
            | termios::ISTRIP
            | termios::INLCR
            | termios::IGNCR
            | termios::ISIG
            | termios::ICRNL
            | termios::IXON);
        termios.c_oflag |= termios::OPOST;
        termios.c_cflag &= !(termios::CSIZE | termios::PARENB);
        termios.c_cflag |= termios::CS8;
        termios.c_cc[termios::VMIN] = 1;
        termios.c_cc[termios::VTIME] = 0;

        tcsetattr(stdin, TCSANOW, &termios).unwrap();

        Self {
            stdin,
            orig_termios,
            pending: VecDeque::new(),
            exit_flag,
            snapshot_flag,
            verbose_flag,
            speedometer_flag,
            tracing_flag,
            awaiting_command: false,
        }
    }

    /// Returns `true` if stdin has at least one byte ready to read
    /// (non-blocking).
    fn stdin_ready(&self) -> bool {
        unsafe {
            let mut pfd = libc::pollfd {
                fd: self.stdin,
                events: libc::POLLIN,
                revents: 0,
            };
            libc::poll(&mut pfd, 1, 0) > 0
        }
    }

    /// Drain everything currently readable and queue guest-bound bytes.
    ///
    /// Reads the raw fd directly rather than through `io::stdin()`: `Stdin`'s
    /// internal `BufReader` would slurp all available bytes off the fd on the
    /// first read, leaving `stdin_ready()`'s `poll()` (which sees only the fd,
    /// not the BufReader) unable to notice them — stranding the tail of a paste
    /// or a multi-byte escape sequence (e.g. an arrow key's `ESC [ A`) until
    /// the next unrelated keystroke shook them loose one at a time.
    fn pump(&mut self) {
        while self.stdin_ready() {
            let mut buf = [0u8; 256];
            // SAFETY: `self.stdin` is a valid fd and `buf` is a valid writable
            // region of `buf.len()` bytes. `poll()` reported readable data and
            // VMIN=1/VTIME=0 means the read returns available bytes without
            // blocking.
            let n = unsafe { libc::read(self.stdin, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            #[allow(clippy::cast_sign_loss)]
            for &byte in &buf[..n as usize] {
                self.feed(byte);
            }
        }
    }

    /// Run one raw input byte through the Ctrl-C command state machine,
    /// queueing it for the guest unless it is the menu prefix (Ctrl-C) or a
    /// command that follows it (handled here as a host-side side effect).
    fn feed(&mut self, got: u8) {
        if self.awaiting_command {
            self.awaiting_command = false;
            if self.handle_command(got) {
                return;
            }
            self.pending.push_back(got); // not a command — pass through to guest
        } else if got == 3 {
            self.awaiting_command = true; // swallow Ctrl-C; next byte is the command
        } else {
            self.pending.push_back(got);
        }
    }

    /// Try to handle `key` as a command. Returns `true` if consumed.
    fn handle_command(&mut self, key: u8) -> bool {
        match key as char {
            '?' => {
                let verbose = self.verbose_flag.load(Ordering::Relaxed);
                let speedometer = self.speedometer_flag.load(Ordering::Relaxed);
                let tracing = self.tracing_flag.load(Ordering::Relaxed);
                eprintln!(
                    "[[v - Verbose({verbose}), S - Speedometer({speedometer}), \
                     t - Tracing({tracing}), s - Save snapshot, x - eXit, \
                     else pass to guest]]"
                );
            }
            't' => {
                self.tracing_flag.fetch_xor(true, Ordering::Relaxed);
            }
            'v' => {
                self.verbose_flag.fetch_xor(true, Ordering::Relaxed);
            }
            's' => {
                // Save a snapshot without stopping; the run loop honors this.
                self.snapshot_flag.store(true, Ordering::Relaxed);
            }
            'S' => {
                self.speedometer_flag.fetch_xor(true, Ordering::Relaxed);
            }
            'x' | 'X' => {
                self.exit_flag.store(true, Ordering::Relaxed);
            }
            _ => return false,
        }
        true
    }

    /// Drain host input and process host-side control keys (the Ctrl-C menu),
    /// buffering guest-bound bytes. Safe to call even when the device cannot
    /// accept a byte yet, so the menu keeps working while the guest's receive
    /// FIFO is full.
    pub fn poll(&mut self) { self.pump(); }

    /// Next guest-bound byte, or `None` if nothing is buffered or readable.
    pub fn get_key(&mut self) -> Option<u8> {
        if self.pending.is_empty() {
            self.pump();
        }
        self.pending.pop_front()
    }
}

impl Drop for NonblockNoEcho {
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn drop(&mut self) {
        // reset the stdin to original termios data
        termios::tcsetattr(self.stdin, termios::TCSANOW, &self.orig_termios).unwrap();
    }
}

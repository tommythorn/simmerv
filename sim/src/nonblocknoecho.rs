use std::io;
use std::io::Read;
use std::io::Stdin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

pub struct NonblockNoEcho {
    stdin: i32,
    orig_termios: termios::Termios,
    reader: Stdin,
    exit_flag: Arc<AtomicBool>,
    snapshot_flag: Arc<AtomicBool>,
    verbose_flag: Arc<AtomicBool>,
    speedometer_flag: Arc<AtomicBool>,
    pub tracing_flag: Arc<AtomicBool>,
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
            reader: io::stdin(),
            exit_flag,
            snapshot_flag,
            verbose_flag,
            speedometer_flag,
            tracing_flag,
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

    pub fn get_key(&mut self) -> Option<u8> {
        if !self.stdin_ready() {
            return None;
        }

        let mut buffer = [0; 1]; // read exactly one byte
        let got = self.reader.read(&mut buffer).map_or(None, |n| {
            assert!(n == 1);
            Some(buffer[0])
        })?;

        if got == 3 {
            let verbose = self.verbose_flag.load(Ordering::Relaxed);
            let speedometer = self.speedometer_flag.load(Ordering::Relaxed);
            let tracing = self.tracing_flag.load(Ordering::Relaxed);
            eprintln!(
                "[[v - Verbose({verbose}), s - Speedometer({speedometer}), t - Tracing({tracing}), x - eXit+snapshot, else, pass on to guest]]"
            );
            loop {
                if !self.stdin_ready() {
                    continue;
                }
                let Some(snd) = self.reader.read(&mut buffer).map_or(None, |n| {
                    assert!(n == 1);
                    Some(buffer[0])
                }) else {
                    continue;
                };

                match snd as char {
                    't' => {
                        let was = self.tracing_flag.fetch_xor(true, Ordering::Relaxed);
                        eprintln!("Tracing {}", if was { "OFF" } else { "ON" });
                    }
                    'v' => {
                        let was = self.verbose_flag.fetch_xor(true, Ordering::Relaxed);
                        eprintln!("Verbose {}", if was { "OFF" } else { "ON" });
                    }
                    's' => {
                        let was = self.speedometer_flag.fetch_xor(true, Ordering::Relaxed);
                        eprintln!("Speedometer {}", if was { "OFF" } else { "ON" });
                    }
                    'x' => {
                        self.snapshot_flag.store(true, Ordering::Relaxed);
                        self.exit_flag.store(true, Ordering::Relaxed);
                        return None;
                    }
                    _ => return Some(snd),
                }
                return None;
            }
        } else {
            Some(buffer[0])
        }
    }
}

impl Drop for NonblockNoEcho {
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn drop(&mut self) {
        // reset the stdin to original termios data
        termios::tcsetattr(self.stdin, termios::TCSANOW, &self.orig_termios).unwrap();
    }
}

use std::io::{self, Read, Stdin};
use termios;

pub struct NonblockNoEcho {
    stdin: i32,
    orig_termios: termios::Termios,
    reader: Stdin,
}

impl NonblockNoEcho {
    pub fn new(capture_ctrlc: bool) -> Self {
        use std::os::unix::io::AsRawFd;
        use termios::*;
        let stdin: i32 = std::io::stdin().as_raw_fd();
        assert_eq!(stdin, 0);

        unsafe {
            let flags = libc::fcntl(stdin, libc::F_GETFL);
            libc::fcntl(stdin, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let orig_termios = Termios::from_fd(stdin).unwrap();

        let mut termios = orig_termios;
        termios.c_lflag &= !(ECHO | ICANON); // no echo and canonical mode
        if capture_ctrlc {
            termios.c_lflag &= !ISIG; // Don't break on Ctrl-C
        }

        /*
        AFAICT, I don't actually need any of all of this

        termios.c_lflag &= !(ECHO | ECHONL | ICANON | IEXTEN); // no echo and canonical mode
        termios.c_iflag &= !(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
        termios.c_oflag |= OPOST;
        termios.c_cflag &= !(CSIZE | PARENB);
        termios.c_cflag |= CS8;
        termios.c_cc[VMIN] = 1;
        termios.c_cc[VTIME] = 0;
         */
        tcsetattr(stdin, TCSANOW, &termios).unwrap();

        Self {
            stdin,
            orig_termios,
            reader: io::stdin(),
        }
    }

    pub fn get_key(&mut self) -> Option<u8> {
        let mut buffer = [0; 1]; // read exactly one byte
        if let Ok(n) = self.reader.read(&mut buffer) {
            assert!(n == 1);
            Some(buffer[0])
        } else {
            None
        }
    }
}

impl Drop for NonblockNoEcho {
    fn drop(&mut self) {
        // reset the stdin to original termios data
        termios::tcsetattr(self.stdin, termios::TCSANOW, &self.orig_termios).unwrap();
        unsafe {
            let flags = libc::fcntl(self.stdin, libc::F_GETFL);
            libc::fcntl(self.stdin, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
}

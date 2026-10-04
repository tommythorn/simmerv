//! Terminal input as key presses, for typing into the graphics console when it
//! is drawn in the terminal rather than in a window.
//!
//! A terminal hands us bytes, not keys: the key presses have to be rebuilt
//! from ASCII (US layout), control characters, and xterm's escape sequences.

use simmerv::device::virtio_input::Keyboard;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

// Linux keycodes (include/uapi/linux/input-event-codes.h).
const ESC: u16 = 1;
const BACKSPACE: u16 = 14;
const TAB: u16 = 15;
const ENTER: u16 = 28;
const LEFTCTRL: u16 = 29;
const LEFTSHIFT: u16 = 42;
const LEFTALT: u16 = 56;
const SPACE: u16 = 57;
const F1: u16 = 59;
const F11: u16 = 87;
const F12: u16 = 88;
const HOME: u16 = 102;
const UP: u16 = 103;
const PAGEUP: u16 = 104;
const LEFT: u16 = 105;
const RIGHT: u16 = 106;
const END: u16 = 107;
const DOWN: u16 = 108;
const PAGEDOWN: u16 = 109;
const INSERT: u16 = 110;
const DELETE: u16 = 111;

const SHIFT: u8 = 1;
const ALT: u8 = 2;
const CTRL: u8 = 4;

/// Where terminal keystrokes go: the serial port, or, while `active`, the
/// virtio keyboard once one has been attached.  Shared between the terminal
/// and `main`, which only learns about the keyboard after the terminal exists.
#[derive(Clone, Default)]
pub struct KeyRoute {
    pub keyboard: Arc<OnceLock<Keyboard>>,
    pub active: Arc<AtomicBool>,
}

impl KeyRoute {
    /// The keyboard, if keystrokes should go to it rather than the serial port.
    pub fn target(&self) -> Option<&Keyboard> {
        self.keyboard
            .get()
            .filter(|_| self.active.load(Ordering::Relaxed))
    }
}

/// Linux keycode and the Shift it needs for printable ASCII `c`, US layout.
fn ascii_key(c: u8) -> Option<(u16, u8)> {
    use simmerv::device::virtio_input::hid_to_linux;
    let (usage, shift) = match c {
        b'a'..=b'z' => (4 + u32::from(c - b'a'), false),
        b'A'..=b'Z' => (4 + u32::from(c - b'A'), true),
        b'1'..=b'9' => (0x1e + u32::from(c - b'1'), false),
        b'0' => (0x27, false),
        b' ' => return Some((SPACE, 0)),
        _ => {
            const PUNCT: &[(u8, u8, u32)] = &[
                (b'-', b'_', 0x2d),
                (b'=', b'+', 0x2e),
                (b'[', b'{', 0x2f),
                (b']', b'}', 0x30),
                (b'\\', b'|', 0x31),
                (b';', b':', 0x33),
                (b'\'', b'"', 0x34),
                (b'`', b'~', 0x35),
                (b',', b'<', 0x36),
                (b'.', b'>', 0x37),
                (b'/', b'?', 0x38),
                (b'1', b'!', 0x1e),
                (b'2', b'@', 0x1f),
                (b'3', b'#', 0x20),
                (b'4', b'$', 0x21),
                (b'5', b'%', 0x22),
                (b'6', b'^', 0x23),
                (b'7', b'&', 0x24),
                (b'8', b'*', 0x25),
                (b'9', b'(', 0x26),
                (b'0', b')', 0x27),
            ];
            let &(plain, _, usage) = PUNCT
                .iter()
                .find(|&&(plain, shifted, _)| c == plain || c == shifted)?;
            (usage, c != plain)
        }
    };
    Some((hid_to_linux(usage)?, if shift { SHIFT } else { 0 }))
}

/// The key a single byte stands for, outside an escape sequence.
fn byte_key(b: u8) -> Option<(u16, u8)> {
    match b {
        b'\r' | b'\n' => Some((ENTER, 0)),
        b'\t' => Some((TAB, 0)),
        0x7f | 0x08 => Some((BACKSPACE, 0)),
        0x1b => Some((ESC, 0)),
        0x00 => Some((SPACE, CTRL)),
        0x01..=0x1a => ascii_key(b'a' + b - 1).map(|(k, _)| (k, CTRL)),
        0x1c..=0x1f => ascii_key(b"\\]^_"[usize::from(b - 0x1c)]).map(|(k, m)| (k, m | CTRL)),
        _ => ascii_key(b),
    }
}

/// The key a CSI (`ESC [`) or SS3 (`ESC O`) sequence names: its parameters and
/// final byte.  The second parameter, when present, is xterm's 1 + modifiers.
fn sequence_key(params: &[u16], fin: u8) -> Option<(u16, u8)> {
    #[allow(clippy::cast_possible_truncation)] // a modifier parameter is tiny
    let mods = params
        .get(1)
        .map_or(0, |&m| (m.saturating_sub(1) as u8) & (SHIFT | ALT | CTRL));
    let key = match fin {
        b'A' => UP,
        b'B' => DOWN,
        b'C' => RIGHT,
        b'D' => LEFT,
        b'H' => HOME,
        b'F' => END,
        b'P'..=b'S' => F1 + u16::from(fin - b'P'),
        b'Z' => return Some((TAB, SHIFT)),
        b'~' => match params.first()? {
            1 | 7 => HOME,
            2 => INSERT,
            3 => DELETE,
            4 | 8 => END,
            5 => PAGEUP,
            6 => PAGEDOWN,
            n @ 11..=15 => F1 + n - 11,
            n @ 17..=21 => F1 + 5 + n - 17,
            23 => F11,
            24 => F12,
            _ => return None,
        },
        _ => return None,
    };
    Some((key, mods))
}

/// Translate one read's worth of terminal input into key presses.
///
/// A whole read at a time because an escape sequence arrives in one piece:
/// an ESC that ends the input is the Esc key itself, and one followed by an
/// ordinary character is Alt held with it.
pub fn translate(input: &[u8]) -> Vec<(u16, u8)> {
    let mut keys = Vec::new();
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        i += 1;
        if b != 0x1b || i == input.len() {
            keys.extend(byte_key(b));
            continue;
        }
        let next = input[i];
        if next == b'[' || next == b'O' {
            // Parameters, then a final byte in 0x40..=0x7e.
            let mut params = vec![0u16];
            let mut j = i + 1;
            while let Some(&c) = input.get(j) {
                j += 1;
                match c {
                    b'0'..=b'9' => {
                        if let Some(p) = params.last_mut() {
                            *p = p.saturating_mul(10).saturating_add(u16::from(c - b'0'));
                        }
                    }
                    b';' => params.push(0),
                    0x40..=0x7e => {
                        keys.extend(sequence_key(&params, c));
                        break;
                    }
                    _ => break,
                }
            }
            i = j;
        } else {
            keys.extend(byte_key(next).map(|(k, m)| (k, m | ALT)));
            i += 1;
        }
    }
    keys
}

/// Press and release each key, with its modifiers held around it.
pub fn send(keyboard: &Keyboard, keys: &[(u16, u8)]) {
    for &(key, mods) in keys {
        let held: Vec<u16> = [(CTRL, LEFTCTRL), (SHIFT, LEFTSHIFT), (ALT, LEFTALT)]
            .into_iter()
            .filter(|&(bit, _)| mods & bit != 0)
            .map(|(_, code)| code)
            .collect();
        for &m in &held {
            keyboard.key(m, true);
        }
        keyboard.key(key, true);
        keyboard.key(key, false);
        for &m in held.iter().rev() {
            keyboard.key(m, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_control_characters() {
        assert_eq!(translate(b"lS /\r"), [
            (38, 0),
            (31, SHIFT),
            (SPACE, 0),
            (53, 0),
            (ENTER, 0)
        ]);
        assert_eq!(translate(b"|\x7f\t"), [
            (43, SHIFT),
            (BACKSPACE, 0),
            (TAB, 0)
        ]);
        // Ctrl-A, Ctrl-D.
        assert_eq!(translate(b"\x01\x04"), [(30, CTRL), (32, CTRL)]);
    }

    #[test]
    fn escape_sequences() {
        assert_eq!(translate(b"\x1b"), [(ESC, 0)]);
        assert_eq!(translate(b"\x1b[A\x1bOD"), [(UP, 0), (LEFT, 0)]);
        assert_eq!(translate(b"\x1b[3~\x1b[24~"), [(DELETE, 0), (F12, 0)]);
        assert_eq!(translate(b"\x1bOP\x1b[15~"), [(F1, 0), (F1 + 4, 0)]);
        // Ctrl-Up, as xterm reports it.
        assert_eq!(translate(b"\x1b[1;5A"), [(UP, CTRL)]);
        // Alt-x.
        assert_eq!(translate(b"\x1bx"), [(45, ALT)]);
    }
}

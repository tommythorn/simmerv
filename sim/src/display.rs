//! Showing the guest's RGB565 framebuffer on the host.
//!
//! SDL2 when a window can be opened, otherwise iTerm2's inline-image escape
//! sequence on the console.  SDL is `dlopen`ed rather than linked, so neither
//! building nor running without `--graphics` needs it installed; a missing
//! library is just one more reason to fall back to the terminal.

use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_void;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use simmerv::device::virtio_input::Keyboard;
use simmerv::device::virtio_input::hid_to_linux;

/// Where frames go, and how often the run loop should hand one over.
pub struct Display {
    pub refresh: simmerv::DisplaySink,
    pub period: Duration,
    /// Drawn in the terminal rather than in a window of its own.
    pub in_terminal: bool,
}

/// Open the best display available for a `width` x `height` framebuffer.
/// Closing the SDL window sets `exit_flag`; keys typed into it go to
/// `keyboard`.  The terminal fallback has no keyboard of its own.
pub fn open(width: u32, height: u32, keyboard: Keyboard, exit_flag: Arc<AtomicBool>) -> Display {
    match Sdl::open(width, height, keyboard) {
        Ok(mut sdl) => Display {
            refresh: Box::new(move |fb| {
                if sdl.present(fb) {
                    exit_flag.store(true, Ordering::Relaxed);
                }
            }),
            period: Duration::from_millis(33),
            in_terminal: false,
        },
        Err(e) => {
            eprintln!("graphics: no SDL window ({e}); drawing in the terminal at 1 Hz instead");
            if !is_iterm2() {
                eprintln!(
                    "graphics: this does not look like iTerm2; frames use its inline-image \
                     protocol and may not show"
                );
            }
            let mut iterm = Iterm2 {
                width,
                height,
                last: Vec::new(),
            };
            Display {
                refresh: Box::new(move |fb| iterm.present(fb)),
                period: Duration::from_secs(1),
                in_terminal: true,
            }
        }
    }
}

fn is_iterm2() -> bool {
    std::env::var("TERM_PROGRAM").is_ok_and(|v| v == "iTerm.app")
        || std::env::var("LC_TERMINAL").is_ok_and(|v| v == "iTerm2")
}

// SDL2's ABI, just the part used here.
const SDL_INIT_VIDEO: u32 = 0x20;
const SDL_WINDOWPOS_UNDEFINED: c_int = 0x1FFF_0000;
const SDL_WINDOW_SHOWN: u32 = 0x4;
const SDL_WINDOW_RESIZABLE: u32 = 0x20;
/// `SDL_DEFINE_PIXELFORMAT(PACKED16, XRGB, 565, 16, 2)`: a native-endian u16,
/// which on a little-endian host is the guest's byte order as is.
const SDL_PIXELFORMAT_RGB565: u32 = 0x1515_1002;
const SDL_TEXTUREACCESS_STREAMING: c_int = 1;
const SDL_QUIT: u32 = 0x100;
const SDL_WINDOWEVENT: u32 = 0x200;
const SDL_WINDOWEVENT_FOCUS_LOST: u8 = 13;
const SDL_KEYDOWN: u32 = 0x300;
const SDL_KEYUP: u32 = 0x301;

type Ptr = *mut c_void;

struct Sdl {
    get_error: unsafe extern "C" fn() -> *const c_char,
    update_texture: unsafe extern "C" fn(Ptr, *const c_void, *const c_void, c_int) -> c_int,
    render_clear: unsafe extern "C" fn(Ptr) -> c_int,
    render_copy: unsafe extern "C" fn(Ptr, Ptr, *const c_void, *const c_void) -> c_int,
    render_present: unsafe extern "C" fn(Ptr),
    poll_event: unsafe extern "C" fn(*mut c_void) -> c_int,
    renderer: Ptr,
    texture: Ptr,
    pitch: c_int,
    keyboard: Keyboard,
    /// Linux keycodes currently down, released if the window loses focus so a
    /// key let go elsewhere does not stay stuck in the guest.
    held: Vec<u16>,
}

/// `dlsym` `name` as a function of type `F`.
///
/// # Safety
/// `F` must be the symbol's real signature.
unsafe fn sym<F: Copy>(lib: Ptr, name: &str) -> Result<F, String> {
    let cname = CString::new(name).map_err(|e| e.to_string())?;
    let p = unsafe { libc::dlsym(lib, cname.as_ptr()) };
    if p.is_null() {
        return Err(format!("{name} not found in SDL2"));
    }
    assert_eq!(size_of::<F>(), size_of::<Ptr>());
    Ok(unsafe { std::mem::transmute_copy(&p) })
}

impl Sdl {
    const LIBRARIES: [&str; 5] = [
        "libSDL2-2.0.so.0",
        "libSDL2.so",
        "libSDL2-2.0.0.dylib",
        "/opt/homebrew/lib/libSDL2-2.0.0.dylib",
        "/usr/local/lib/libSDL2-2.0.0.dylib",
    ];

    fn open(width: u32, height: u32, keyboard: Keyboard) -> Result<Self, String> {
        let lib = Self::LIBRARIES
            .iter()
            .find_map(|name| {
                let cname = CString::new(*name).ok()?;
                let lib = unsafe { libc::dlopen(cname.as_ptr(), libc::RTLD_NOW) };
                (!lib.is_null()).then_some(lib)
            })
            .ok_or("can't load libSDL2")?;

        // SAFETY: each signature is SDL2's own, from SDL.h.
        unsafe {
            let set_hint: unsafe extern "C" fn(*const c_char, *const c_char) -> c_int =
                sym(lib, "SDL_SetHint")?;
            let init: unsafe extern "C" fn(u32) -> c_int = sym(lib, "SDL_Init")?;
            let create_window: unsafe extern "C" fn(
                *const c_char,
                c_int,
                c_int,
                c_int,
                c_int,
                u32,
            ) -> Ptr = sym(lib, "SDL_CreateWindow")?;
            let create_renderer: unsafe extern "C" fn(Ptr, c_int, u32) -> Ptr =
                sym(lib, "SDL_CreateRenderer")?;
            let set_logical_size: unsafe extern "C" fn(Ptr, c_int, c_int) -> c_int =
                sym(lib, "SDL_RenderSetLogicalSize")?;
            let create_texture: unsafe extern "C" fn(Ptr, u32, c_int, c_int, c_int) -> Ptr =
                sym(lib, "SDL_CreateTexture")?;
            let sdl = Self {
                get_error: sym(lib, "SDL_GetError")?,
                update_texture: sym(lib, "SDL_UpdateTexture")?,
                render_clear: sym(lib, "SDL_RenderClear")?,
                render_copy: sym(lib, "SDL_RenderCopy")?,
                render_present: sym(lib, "SDL_RenderPresent")?,
                poll_event: sym(lib, "SDL_PollEvent")?,
                renderer: std::ptr::null_mut(),
                texture: std::ptr::null_mut(),
                pitch: 0,
                keyboard,
                held: Vec::new(),
            };
            let error = || {
                CStr::from_ptr((sdl.get_error)())
                    .to_string_lossy()
                    .into_owned()
            };

            // The console is in raw mode and Ctrl-C is the emulator's menu key;
            // SDL must not turn SIGINT into a quit event behind its back.
            set_hint(c"SDL_NO_SIGNAL_HANDLERS".as_ptr(), c"1".as_ptr());
            if init(SDL_INIT_VIDEO) != 0 {
                return Err(error());
            }
            // With no desktop SDL happily falls through to KMSDRM or a dummy
            // driver, which "succeeds" without showing anything.  Unless the
            // user chose a driver, only one that opens a window will do.
            let driver: unsafe extern "C" fn() -> *const c_char =
                sym(lib, "SDL_GetCurrentVideoDriver")?;
            let driver = driver();
            let driver = if driver.is_null() {
                String::new()
            } else {
                CStr::from_ptr(driver).to_string_lossy().into_owned()
            };
            if std::env::var_os("SDL_VIDEODRIVER").is_none()
                && !["x11", "wayland", "cocoa", "windows"].contains(&driver.as_str())
            {
                let quit: unsafe extern "C" fn() = sym(lib, "SDL_Quit")?;
                quit();
                return Err(format!("SDL found no windowing system, only {driver:?}"));
            }
            let (w, h) = (width as c_int, height as c_int);
            let window = create_window(
                c"simmerv".as_ptr(),
                SDL_WINDOWPOS_UNDEFINED,
                SDL_WINDOWPOS_UNDEFINED,
                w,
                h,
                SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE,
            );
            if window.is_null() {
                return Err(error());
            }
            // No PRESENTVSYNC: presenting runs on the emulator's own thread,
            // and waiting for vblank there would stall the guest.
            let renderer = create_renderer(window, -1, 0);
            if renderer.is_null() {
                return Err(error());
            }
            // Scales a resized window, letterboxed to the guest's aspect.
            set_logical_size(renderer, w, h);
            let texture = create_texture(
                renderer,
                SDL_PIXELFORMAT_RGB565,
                SDL_TEXTUREACCESS_STREAMING,
                w,
                h,
            );
            if texture.is_null() {
                return Err(error());
            }
            Ok(Self {
                renderer,
                texture,
                pitch: w * 2,
                ..sdl
            })
        }
    }

    /// Show `fb` and drain the event queue; true when the window was closed.
    fn present(&mut self, fb: &[u8]) -> bool {
        let mut quit = false;
        // SAFETY: the handles were created in `open` and live for the process,
        // `fb` is `pitch * height` bytes (the emulator's `visible_len`), and
        // `event` is larger than the 56-byte `SDL_Event`.
        unsafe {
            (self.update_texture)(
                self.texture,
                std::ptr::null(),
                fb.as_ptr().cast(),
                self.pitch,
            );
            (self.render_clear)(self.renderer);
            (self.render_copy)(
                self.renderer,
                self.texture,
                std::ptr::null(),
                std::ptr::null(),
            );
            (self.render_present)(self.renderer);
            let mut event = [0u64; 8];
            while (self.poll_event)(event.as_mut_ptr().cast()) != 0 {
                quit |= self.handle(&event);
            }
        }
        quit
    }

    /// Act on one `SDL_Event`; true for a quit.
    fn handle(&mut self, event: &[u64; 8]) -> bool {
        let bytes: Vec<u8> = event.iter().flat_map(|w| w.to_ne_bytes()).collect();
        let u32_at = |off: usize| {
            u32::from_ne_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
        };
        match u32_at(0) {
            SDL_QUIT => return true,
            // SDL_KeyboardEvent: type, timestamp, windowID, state, repeat,
            // padding, then SDL_Keysym.scancode at 16 -- a USB HID usage.
            kind @ (SDL_KEYDOWN | SDL_KEYUP) => {
                let down = kind == SDL_KEYDOWN;
                // The guest autorepeats on its own (the device has EV_REP).
                let repeat = bytes[13] != 0;
                if let Some(code) = hid_to_linux(u32_at(16))
                    && !repeat
                {
                    self.held.retain(|&c| c != code);
                    if down {
                        self.held.push(code);
                    }
                    self.keyboard.key(code, down);
                }
            }
            // SDL_WindowEvent: type, timestamp, windowID, event.
            SDL_WINDOWEVENT if bytes[12] == SDL_WINDOWEVENT_FOCUS_LOST => {
                for code in self.held.drain(..) {
                    self.keyboard.key(code, false);
                }
            }
            _ => {}
        }
        false
    }
}

/// Frames as iTerm2 inline images, printed at the cursor.
struct Iterm2 {
    width: u32,
    height: u32,
    /// The last frame shown; an unchanged screen is not printed again.
    last: Vec<u8>,
}

impl Iterm2 {
    fn present(&mut self, fb: &[u8]) {
        if fb == self.last.as_slice() {
            return;
        }
        self.last.clear();
        self.last.extend_from_slice(fb);
        let bmp = rgb565_bmp(self.width, self.height, fb);
        let mut out = std::io::stdout().lock();
        // Home the cursor so each frame overdraws the last instead of
        // scrolling; console output then resumes below the image (`\r\n`:
        // the console is in raw mode).
        let _ = write!(
            out,
            "\x1b[H\x1b]1337;File=inline=1;size={};preserveAspectRatio=1:{}\x07\r\n",
            bmp.len(),
            base64(&bmp)
        );
        let _ = out.flush();
    }
}

/// A 16-bit `BI_BITFIELDS` BMP: RGB565 rows exactly as the guest wrote them.
fn rgb565_bmp(width: u32, height: u32, fb: &[u8]) -> Vec<u8> {
    let stride = width as usize * 2;
    let padded = (stride + 3) & !3;
    let header = 14 + 40 + 12;
    let image = padded * height as usize;
    let mut bmp = Vec::with_capacity(header + image);
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&((header + image) as u32).to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&(header as u32).to_le_bytes());
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&(width as i32).to_le_bytes());
    // Negative height: top-down rows, the framebuffer's own order.
    bmp.extend_from_slice(&(-(height as i32)).to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&16u16.to_le_bytes());
    bmp.extend_from_slice(&3u32.to_le_bytes()); // BI_BITFIELDS
    bmp.extend_from_slice(&(image as u32).to_le_bytes());
    bmp.extend_from_slice(&[0; 16]); // resolution, palette
    for mask in [0xf800u32, 0x07e0, 0x001f] {
        bmp.extend_from_slice(&mask.to_le_bytes());
    }
    for row in fb.chunks_exact(stride).take(height as usize) {
        bmp.extend_from_slice(row);
        bmp.resize(bmp.len() + padded - stride, 0);
    }
    bmp
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

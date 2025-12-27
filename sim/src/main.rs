mod dummy_terminal;
mod nonblocknoecho;
mod popup_terminal;

use crate::dummy_terminal::DummyTerminal;
use crate::popup_terminal::PopupTerminal;
use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use argh::FromArgs;
use simmerv::Emulator;
use simmerv::terminal::Terminal;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;

#[derive(FromArgs)]
#[allow(clippy::doc_markdown)]
#[allow(clippy::struct_excessive_bools)]
/// Simulate a RISC-V RV64GC System on Chip
struct Args {
    /// file system image files
    #[argh(option, short = 'f')]
    fs: Vec<String>,

    /// device Tree Binary
    #[argh(option, short = 'd')]
    dtb: Option<String>,

    /// no popup terminal
    #[argh(switch, short = 'n')]
    no_terminal: bool,

    /// memory size in megabytes (doesn't yet update the device tree)
    #[argh(option, short = 'm')]
    memory_megs: Option<usize>,

    /// run with tracing
    #[argh(switch, short = 't')]
    tracing: bool,

    /// enable experimental page cache optimization
    #[argh(switch, short = 'p')]
    page_cache: bool,

    /// allow ctrl-C to terminate app
    #[argh(switch, short = 'c')]
    ctrlc_breaks: bool,

    /// memory images, with optional comma separated options,
    /// such as '0x8200000'
    #[argh(positional)]
    images: Vec<String>,
}

enum TerminalType {
    PopupTerminal,
    DummyTerminal,
}

fn get_terminal(terminal_type: &TerminalType, ctrlc_breaks: bool) -> Box<dyn Terminal> {
    match terminal_type {
        TerminalType::PopupTerminal => Box::new(PopupTerminal::new(ctrlc_breaks)),
        TerminalType::DummyTerminal => Box::new(DummyTerminal::new()),
    }
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args: Args = argh::from_env();
    let terminal_type = if args.no_terminal {
        TerminalType::DummyTerminal
    } else {
        TerminalType::PopupTerminal
    };
    let mut symbols = BTreeMap::new();
    let memory_megs = args.memory_megs.unwrap_or(2048);
    let mut emulator = Emulator::new(
        get_terminal(&terminal_type, args.ctrlc_breaks),
        memory_megs * 1024 * 1024,
    );
    let mut img_contents = vec![];
    let mut load_addr = None;
    let mut emu_start = None;
    let mut images = 0;

    for img_path in args.images {
        img_contents.clear();
        let mut parts_iter = img_path.split(',');
        let filename = parts_iter.next().unwrap_or("");
        let mut img_file = File::open(filename).with_context(|| filename.to_string())?;
        img_file
            .read_to_end(&mut img_contents)
            .with_context(|| filename.to_string())?;

        for part in parts_iter {
            if &part[..2] == "0x" {
                load_addr = Some(u64::from_str_radix(&part[2..], 16)?);
            } else {
                bail!("Unsupported file option {part}");
            }
        }

        let entry = emulator
            .load_image(filename, &img_contents, load_addr, &mut symbols)
            .with_context(|| filename.to_string())
            .map_err(|e| anyhow!(e))?;

        images += 1;

        if emu_start.is_none() {
            emu_start = Some(entry);
        }

        if let Some(addr) = symbols.get("tohost") {
            emulator.tohost_addr = *addr;
        }

        load_addr = None;
    }

    if let Some(path) = args.dtb {
        let mut file = File::open(&path).with_context(|| path.to_string())?;
        let mut contents = vec![];
        file.read_to_end(&mut contents)?;
        emulator.setup_dtb(&contents);
    }

    for path in args.fs {
        emulator.setup_filesystem(if path.ends_with(".zst") {
            let file = File::open(&path).with_context(|| path.to_string())?;
            zstd::stream::decode_all(file)?
        } else {
            let mut file = File::open(&path).with_context(|| path.to_string())?;
            let mut contents = vec![];
            file.read_to_end(&mut contents)?;
            contents
        });
    }

    emulator.enable_page_cache(args.page_cache);

    if images == 0 {
        bail!("I have nothing to run");
    }

    emulator.cpu.update_pc(emu_start.unwrap_or(0x8000_0000));

    emulator.run(args.tracing);

    Ok(())
}

mod dummy_terminal;
mod nonblocknoecho;
mod popup_terminal;

use crate::dummy_terminal::DummyTerminal;
use crate::popup_terminal::PopupTerminal;
use anyhow::anyhow;
use anyhow::bail;
use argh::FromArgs;
use simmerv::Emulator;
use simmerv::terminal::Terminal;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;

#[derive(FromArgs)]
/// Simulate a RISC-V RV64GC SoC
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

    /// run with tracing
    #[argh(switch, short = 't')]
    tracing: bool,

    /// enable experimental page cache optimization
    #[argh(switch, short = 'p')]
    page_cache: bool,

    /// memory images, with optional comma separated options,
    /// such as '0x8200000'
    #[argh(positional)]
    images: Vec<String>,
}

enum TerminalType {
    PopupTerminal,
    DummyTerminal,
}

fn get_terminal(terminal_type: &TerminalType) -> Box<dyn Terminal> {
    match terminal_type {
        TerminalType::PopupTerminal => Box::new(PopupTerminal::new()),
        TerminalType::DummyTerminal => Box::new(DummyTerminal::new()),
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args: Args = argh::from_env();
    let terminal_type = if args.no_terminal {
        TerminalType::DummyTerminal
    } else {
        TerminalType::PopupTerminal
    };
    let mut symbols = BTreeMap::new();
    let mut emulator = Emulator::new(get_terminal(&terminal_type), 512 * 1024 * 1024);
    let mut img_contents = vec![];
    let mut load_addr = Some(0x8000_0000);
    let mut emu_start = None;

    for img_path in args.images {
        img_contents.clear();
        let mut parts_iter = img_path.split(',');

        let mut img_file = File::open(parts_iter.next().unwrap())?;
        img_file.read_to_end(&mut img_contents)?;

        for part in parts_iter {
            if &part[..2] == "0x" {
                load_addr = Some(u64::from_str_radix(&part[2..], 16)?);
            } else {
                bail!("Unsupported file option {part}");
            }
        }

        let entry = emulator
            .load_image(&img_contents, load_addr, &mut symbols)
            .map_err(|e| anyhow!(e))?;

        if emu_start.is_none() {
            emu_start = Some(entry);
        }

        if let Some(addr) = symbols.get("tohost") {
            emulator.tohost_addr = *addr;
        }

        load_addr = None;
    }

    if let Some(path) = args.dtb {
        let mut file = File::open(path)?;
        let mut contents = vec![];
        file.read_to_end(&mut contents)?;
        emulator.setup_dtb(&contents);
    }

    for path in args.fs {
        let mut file = File::open(path)?;
        let mut contents = vec![];
        file.read_to_end(&mut contents)?;
        emulator.setup_filesystem(contents);
    }

    emulator.enable_page_cache(args.page_cache);

    emulator.cpu.update_pc(emu_start.unwrap());

    emulator.run(args.tracing);

    Ok(())
}

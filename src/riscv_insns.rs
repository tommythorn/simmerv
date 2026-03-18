/// RISC-V `RV64GC_Zba_Zbb_Zbc_Zbs_Zicond_Svinval` (RVA20+) instruction
/// definitions
///
/// This is a dependency-free module that just gives the same and
/// encoding of the `RV64GC_Zba_Zbb_Zbc_Zbs_Zicond_Svinval` instructions, useful
/// for deriving decoders etc.  There is simple utility function that
/// generates the corresponding enum.
pub const INSTRUCTIONS: [(u32, u32, &str); 248] = [
    (0xffff, 0x0000, "c.unimp"), // is a sub-pattern of c.addi4spn
    (0xe003, 0x0000, "c.addi4spn"),
    (0xe003, 0x2000, "c.fld"),
    (0xe003, 0x4000, "c.lw"),
    (0xe003, 0x6000, "c.ld"),
    (0xe003, 0xa000, "c.fsd"),
    (0xe003, 0xc000, "c.sw"),
    (0xe003, 0xe000, "c.sd"),
    (0xffff, 0x0001, "c.nop"), // is a sub-pattern of c.addi
    (0xe003, 0x0001, "c.addi"),
    (0xe003, 0x2001, "c.addiw"),
    (0xe003, 0x4001, "c.li"),
    (0xef83, 0x6101, "c.addi16sp"), // is a sub-pattern of c.lui
    (0xe003, 0x6001, "c.lui"),
    (0xec03, 0x8001, "c.srli"),
    (0xec03, 0x8401, "c.srai"),
    (0xec03, 0x8801, "c.andi"),
    (0xfc63, 0x8c01, "c.sub"),
    (0xfc63, 0x8c21, "c.xor"),
    (0xfc63, 0x8c41, "c.or"),
    (0xfc63, 0x8c61, "c.and"),
    (0xfc63, 0x9c01, "c.subw"),
    (0xfc63, 0x9c21, "c.addw"),
    (0xe003, 0xa001, "c.j"),
    (0xe003, 0xc001, "c.beqz"),
    (0xe003, 0xe001, "c.bnez"),
    (0xe003, 0x0002, "c.slli"),
    (0xe003, 0x2002, "c.fldsp"),
    (0xe003, 0x4002, "c.lwsp"),
    (0xe003, 0x6002, "c.ldsp"),
    (0xf07f, 0x8002, "c.jr"), // is a sub-pattern of c.mv
    (0xf003, 0x8002, "c.mv"),
    (0xffff, 0x9002, "c.ebreak"), // is a sub-pattern of c.jalr, which
    (0xf07f, 0x9002, "c.jalr"),   // is a sub-pattern of c.add
    (0xf003, 0x9002, "c.add"),
    (0xe003, 0xa002, "c.fsdsp"),
    (0xe003, 0xc002, "c.swsp"),
    (0xe003, 0xe002, "c.sdsp"),
    (0x0000007f, 0x00000037, "lui"),
    (0x0000007f, 0x00000017, "auipc"),
    (0x0000007f, 0x0000006f, "jal"),
    (0x0000707f, 0x00000067, "jalr"),
    (0x0000707f, 0x00000063, "beq"),
    (0x0000707f, 0x00001063, "bne"),
    (0x0000707f, 0x00004063, "blt"),
    (0x0000707f, 0x00005063, "bge"),
    (0x0000707f, 0x00006063, "bltu"),
    (0x0000707f, 0x00007063, "bgeu"),
    (0x0000707f, 0x00000003, "lb"),
    (0x0000707f, 0x00001003, "lh"),
    (0x0000707f, 0x00002003, "lw"),
    (0x0000707f, 0x00004003, "lbu"),
    (0x0000707f, 0x00005003, "lhu"),
    (0x0000707f, 0x00000023, "sb"),
    (0x0000707f, 0x00001023, "sh"),
    (0x0000707f, 0x00002023, "sw"),
    (0x0000707f, 0x00000013, "addi"),
    (0x0000707f, 0x00002013, "slti"),
    (0x0000707f, 0x00003013, "sltiu"),
    (0x0000707f, 0x00004013, "xori"),
    (0x0000707f, 0x00006013, "ori"),
    (0x0000707f, 0x00007013, "andi"),
    (0xfe00707f, 0x00000033, "add"),
    (0xfe00707f, 0x40000033, "sub"),
    (0xfe00707f, 0x00001033, "sll"),
    (0xfe00707f, 0x00002033, "slt"),
    (0xfe00707f, 0x00003033, "sltu"),
    (0xfe00707f, 0x00004033, "xor"),
    (0xfe00707f, 0x00005033, "srl"),
    (0xfe00707f, 0x40005033, "sra"),
    (0xfe00707f, 0x00006033, "or"),
    (0xfe00707f, 0x00007033, "and"),
    (0xf000707f, 0x0000000f, "fence"),
    (0xf000707f, 0x8000000f, "fence.tso"),
    (0xffffffff, 0x00000073, "ecall"),
    (0xffffffff, 0x00100073, "ebreak"),
    (0x0000707f, 0x00006003, "lwu"),
    (0x0000707f, 0x00003003, "ld"),
    (0x0000707f, 0x00003023, "sd"),
    (0xfc00707f, 0x00001013, "slli"),
    (0xfc00707f, 0x00005013, "srli"),
    (0xfc00707f, 0x40005013, "srai"),
    (0x0000707f, 0x0000001b, "addiw"),
    (0xfe00707f, 0x0000101b, "slliw"),
    (0xfe00707f, 0x0000501b, "srliw"),
    (0xfe00707f, 0x4000501b, "sraiw"),
    (0xfe00707f, 0x0000003b, "addw"),
    (0xfe00707f, 0x4000003b, "subw"),
    (0xfe00707f, 0x0000103b, "sllw"),
    (0xfe00707f, 0x0000503b, "srlw"),
    (0xfe00707f, 0x4000503b, "sraw"),
    (0xffffffff, 0x0000100f, "fence.i"),
    (0x0000707f, 0x00001073, "csrrw"),
    (0x0000707f, 0x00002073, "csrrs"),
    (0x0000707f, 0x00003073, "csrrc"),
    (0x0000707f, 0x00005073, "csrrwi"),
    (0x0000707f, 0x00006073, "csrrsi"),
    (0x0000707f, 0x00007073, "csrrci"),
    (0xfe00707f, 0x02000033, "mul"),
    (0xfe00707f, 0x02001033, "mulh"),
    (0xfe00707f, 0x02002033, "mulhsu"),
    (0xfe00707f, 0x02003033, "mulhu"),
    (0xfe00707f, 0x02004033, "div"),
    (0xfe00707f, 0x02005033, "divu"),
    (0xfe00707f, 0x02006033, "rem"),
    (0xfe00707f, 0x02007033, "remu"),
    (0xfe00707f, 0x0200003b, "mulw"),
    (0xfe00707f, 0x0200403b, "divw"),
    (0xfe00707f, 0x0200503b, "divuw"),
    (0xfe00707f, 0x0200603b, "remw"),
    (0xfe00707f, 0x0200703b, "remuw"),
    (0xf9f0707f, 0x1000202f, "lr.w"),
    (0xf800707f, 0x1800202f, "sc.w"),
    (0xf800707f, 0x0800202f, "amoswap.w"),
    (0xf800707f, 0x0000202f, "amoadd.w"),
    (0xf800707f, 0x2000202f, "amoxor.w"),
    (0xf800707f, 0x6000202f, "amoand.w"),
    (0xf800707f, 0x4000202f, "amoor.w"),
    (0xf800707f, 0x8000202f, "amomin.w"),
    (0xf800707f, 0xa000202f, "amomax.w"),
    (0xf800707f, 0xc000202f, "amominu.w"),
    (0xf800707f, 0xe000202f, "amomaxu.w"),
    (0xf9f0707f, 0x1000302f, "lr.d"),
    (0xf800707f, 0x1800302f, "sc.d"),
    (0xf800707f, 0x0800302f, "amoswap.d"),
    (0xf800707f, 0x0000302f, "amoadd.d"),
    (0xf800707f, 0x2000302f, "amoxor.d"),
    (0xf800707f, 0x6000302f, "amoand.d"),
    (0xf800707f, 0x4000302f, "amoor.d"),
    (0xf800707f, 0x8000302f, "amomin.d"),
    (0xf800707f, 0xa000302f, "amomax.d"),
    (0xf800707f, 0xc000302f, "amominu.d"),
    (0xf800707f, 0xe000302f, "amomaxu.d"),
    (0x0000707f, 0x00002007, "flw"),
    (0x0000707f, 0x00002027, "fsw"),
    (0x0600007f, 0x00000043, "fmadd.s"),
    (0x0600007f, 0x00000047, "fmsub.s"),
    (0x0600007f, 0x0000004b, "fnmsub.s"),
    (0x0600007f, 0x0000004f, "fnmadd.s"),
    (0xfe00007f, 0x00000053, "fadd.s"),
    (0xfe00007f, 0x08000053, "fsub.s"),
    (0xfe00007f, 0x10000053, "fmul.s"),
    (0xfe00007f, 0x18000053, "fdiv.s"),
    (0xfff0007f, 0x58000053, "fsqrt.s"),
    (0xfe00707f, 0x20000053, "fsgnj.s"),
    (0xfe00707f, 0x20001053, "fsgnjn.s"),
    (0xfe00707f, 0x20002053, "fsgnjx.s"),
    (0xfe00707f, 0x28000053, "fmin.s"),
    (0xfe00707f, 0x28001053, "fmax.s"),
    (0xfff0007f, 0xc0000053, "fcvt.w.s"),
    (0xfff0007f, 0xc0100053, "fcvt.wu.s"),
    (0xfff0707f, 0xe0000053, "fmv.x.w"),
    (0xfe00707f, 0xa0002053, "feq.s"),
    (0xfe00707f, 0xa0001053, "flt.s"),
    (0xfe00707f, 0xa0000053, "fle.s"),
    (0xfff0707f, 0xe0001053, "fclass.s"),
    (0xfff0007f, 0xd0000053, "fcvt.s.w"),
    (0xfff0007f, 0xd0100053, "fcvt.s.wu"),
    (0xfff0707f, 0xf0000053, "fmv.w.x"),
    (0xfff0007f, 0xc0200053, "fcvt.l.s"),
    (0xfff0007f, 0xc0300053, "fcvt.lu.s"),
    (0xfff0007f, 0xd0200053, "fcvt.s.l"),
    (0xfff0007f, 0xd0300053, "fcvt.s.lu"),
    (0x0000707f, 0x00003007, "fld"),
    (0x0000707f, 0x00003027, "fsd"),
    (0x0600007f, 0x02000043, "fmadd.d"),
    (0x0600007f, 0x02000047, "fmsub.d"),
    (0x0600007f, 0x0200004b, "fnmsub.d"),
    (0x0600007f, 0x0200004f, "fnmadd.d"),
    (0xfe00007f, 0x02000053, "fadd.d"),
    (0xfe00007f, 0x0a000053, "fsub.d"),
    (0xfe00007f, 0x12000053, "fmul.d"),
    (0xfe00007f, 0x1a000053, "fdiv.d"),
    (0xfff0007f, 0x5a000053, "fsqrt.d"),
    (0xfe00707f, 0x22000053, "fsgnj.d"),
    (0xfe00707f, 0x22001053, "fsgnjn.d"),
    (0xfe00707f, 0x22002053, "fsgnjx.d"),
    (0xfe00707f, 0x2a000053, "fmin.d"),
    (0xfe00707f, 0x2a001053, "fmax.d"),
    (0xfff0007f, 0x40100053, "fcvt.s.d"),
    (0xfff0007f, 0x42000053, "fcvt.d.s"),
    (0xfe00707f, 0xa2002053, "feq.d"),
    (0xfe00707f, 0xa2001053, "flt.d"),
    (0xfe00707f, 0xa2000053, "fle.d"),
    (0xfff0707f, 0xe2001053, "fclass.d"),
    (0xfff0007f, 0xc2000053, "fcvt.w.d"),
    (0xfff0007f, 0xc2100053, "fcvt.wu.d"),
    (0xfff0007f, 0xd2000053, "fcvt.d.w"),
    (0xfff0007f, 0xd2100053, "fcvt.d.wu"),
    (0xfff0007f, 0xc2200053, "fcvt.l.d"),
    (0xfff0007f, 0xc2300053, "fcvt.lu.d"),
    (0xfff0707f, 0xe2000053, "fmv.x.d"),
    (0xfff0007f, 0xd2200053, "fcvt.d.l"),
    (0xfff0007f, 0xd2300053, "fcvt.d.lu"),
    (0xfff0707f, 0xf2000053, "fmv.d.x"),
    (0xffffffff, 0x7b200073, "dret"),
    (0xffffffff, 0x30200073, "mret"),
    (0xffffffff, 0x10200073, "sret"),
    (0xfe007fff, 0x12000073, "sfence.vma"),
    // Svinval — fine-grained address-translation cache invalidation
    (0xfe007fff, 0x16000073, "sinval.vma"),
    (0xffffffff, 0x18000073, "sfence.w.inval"),
    (0xffffffff, 0x18100073, "sfence.inval.ir"),
    (0xffffffff, 0x10500073, "wfi"),
    (0xfe00707f, 0x0800003b, "add.uw"),
    (0xfe00707f, 0x20002033, "sh1add"),
    (0xfe00707f, 0x2000203b, "sh1add.uw"),
    (0xfe00707f, 0x20004033, "sh2add"),
    (0xfe00707f, 0x2000403b, "sh2add.uw"),
    (0xfe00707f, 0x20006033, "sh3add"),
    (0xfe00707f, 0x2000603b, "sh3add.uw"),
    (0xfe00707f, 0x0800101b, "slli.uw"),
    (0xfe00707f, 0x0e005033, "czero.eqz"),
    (0xfe00707f, 0x0e007033, "czero.nez"),
    // Zbb — base integer bit manipulation (RV64)
    (0xfe00707f, 0x40007033, "andn"),
    (0xfe00707f, 0x40006033, "orn"),
    (0xfe00707f, 0x40004033, "xnor"),
    (0xfff0707f, 0x60001013, "clz"),
    (0xfff0707f, 0x6000101b, "clzw"),
    (0xfff0707f, 0x60101013, "ctz"),
    (0xfff0707f, 0x6010101b, "ctzw"),
    (0xfff0707f, 0x60201013, "cpop"),
    (0xfff0707f, 0x6020101b, "cpopw"),
    (0xfe00707f, 0x0a006033, "max"),
    (0xfe00707f, 0x0a007033, "maxu"),
    (0xfe00707f, 0x0a004033, "min"),
    (0xfe00707f, 0x0a005033, "minu"),
    (0xfff0707f, 0x28705013, "orc.b"),
    (0xfff0707f, 0x6b805013, "rev8"),
    (0xfe00707f, 0x60001033, "rol"),
    (0xfe00707f, 0x6000103b, "rolw"),
    (0xfe00707f, 0x60005033, "ror"),
    (0xfc00707f, 0x60005013, "rori"),
    (0xfe00707f, 0x6000501b, "roriw"),
    (0xfe00707f, 0x6000503b, "rorw"),
    (0xfff0707f, 0x60401013, "sext.b"),
    (0xfff0707f, 0x60501013, "sext.h"),
    (0xfff0707f, 0x0800403b, "zext.h"),
    // Zbs — single-bit instructions
    (0xfe00707f, 0x48001033, "bclr"),
    (0xfc00707f, 0x48001013, "bclri"),
    (0xfe00707f, 0x48005033, "bext"),
    (0xfc00707f, 0x48005013, "bexti"),
    (0xfe00707f, 0x68001033, "binv"),
    (0xfc00707f, 0x68001013, "binvi"),
    (0xfe00707f, 0x28001033, "bset"),
    (0xfc00707f, 0x28001013, "bseti"),
    // Zbc — carry-less multiplication
    (0xfe00707f, 0x0a001033, "clmul"),
    (0xfe00707f, 0x0a003033, "clmulh"),
    (0xfe00707f, 0x0a002033, "clmulr"),
];

fn to_pascal_case(s: &str) -> String {
    let mut result = String::new();
    let mut upcase = true;

    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            if upcase {
                result.push(ch.to_ascii_uppercase());
                upcase = false;
            } else {
                result.push(ch.to_ascii_lowercase());
            }
        } else {
            upcase = true;
        }
    }

    result
}

pub fn generate_enum() {
    println!("// Generated by riscv_insns::generate_enum()");
    println!("#[derive(Debug, Clone, Copy, PartialEq, Eq)]");
    println!("pub enum Op {{");
    for (_, _, name) in INSTRUCTIONS {
        let name: String = to_pascal_case(name);
        println!("    {name},");
    }
    println!("    Unimp,");
    println!("}}");
}

/// Generate a RISC-V instruction decoder function.
///
/// This is very closely tied to the trait definition in
/// `riscv_decoding::RiscvDecoder`
///
/// First we build a fast 2**N-elements dispatch table for accelerated
/// lookup
///
/// For a masked pattern to match here it must be the case that `(W &
/// 0x707f) == index_pattern && (W & mask) == patn` For that to be
/// true it means for bit i in W if it's in 0x707f must match the
/// value of `index_pattern` and if it's in mask it must match patn,
/// thus if it's on both masks (0x707f & mask) then `index_pattern` and
/// `W` must agree.  IOW, we only need to test patterns that agree with
/// `index_pattern` on (0x707f & mask)
pub fn generate_riscv_decoder() {
    const M: u32 = 0xf07f; // ...07f is assumed below
    const N: usize = M.count_ones() as usize;

    // Step 1: correct all the possible instruction in a list per
    // discriminator index

    let mut reverse = std::collections::BTreeMap::new();

    for index in 0..1 << N {
        let index_pattern = (index & 127) | (index >> 7 << 12);
        let mut cands = Vec::new();
        for (i, (mask, pattern, _mnemonic)) in INSTRUCTIONS.iter().enumerate() {
            if (pattern & mask & M) == (index_pattern & mask) {
                cands.push(i);
            }
        }

        // Step 2: gather all idential matches
        let entry = reverse.entry(cands).or_insert(vec![]);
        entry.push(index);
    }

    println!("// Generated by generate_riscv_decoder(), do not hand-edit");
    println!("use crate::riscv_decoding::RiscvDecoder;");
    println!();
    println!("#[allow(clippy::too_many_lines, clippy::verbose_bit_mask, unused_braces)]");
    println!(
        "pub fn decoder<R, C: RiscvDecoder<Context = C, Returns = R>>(a: u64, w: u32, c: &mut C) -> R {{"
    );
    println!("    match (w >> 5 & 0x780) + (w & 0x7f) {{");
    'outer: for (cands, indicies) in reverse {
        let mut cands: Vec<usize> = cands;
        let indicies: Vec<u32> = indicies;

        print!("        ");

        let mut sep = "";
        for i in indicies {
            print!("{sep}{i} ");
            sep = "| ";
        }
        println!("=> {{");
        // 0. sort patterns by bits in mask, mask, pattern
        cands.sort_by(|a, b| {
            let (amask, apatn, _) = INSTRUCTIONS[*a];
            let (bmask, bpatn, _) = INSTRUCTIONS[*b];
            bmask
                .count_ones()
                .cmp(&amask.count_ones())
                .then_with(|| amask.cmp(&bmask))
                .then_with(|| apatn.cmp(&bpatn))
        });

        // 1. compute the longest common span of trailing zeros across masks
        let shift = cands
            .iter()
            .map(|a| (INSTRUCTIONS[*a].0 & !0xf07f).trailing_zeros())
            .min()
            .unwrap_or(0);

        // 2. shift the mask as a *signed* i32 (to enable eliminating
        // an all-1 mask. Make all comparisons use (w >> shift) &
        // {shifted_mask} == {shifted_patn}
        let mut prefix = "            ";
        for i in &cands {
            let (mask, patn, name) = INSTRUCTIONS[*i];
            let mask = mask & !0xf07f;
            let name = name.replace('.', "_");
            if mask != 0 {
                let mask = ((mask & !M).cast_signed()) >> shift;
                let patn = ((patn & !M) >> shift).cast_signed();
                if mask == !0 {
                    println!("{prefix}if (w >> {shift}) == {patn:#x} {{ C::{name}(a, w, c) }}");
                } else {
                    println!(
                        "{prefix}if (w >> {shift}) & {mask:#x} == {patn:#x} {{ C::{name}(a, w, c) }}"
                    );
                }
                prefix = "    else ";
            } else {
                println!("{prefix}{{ C::{name}(a, w, c) }}}}");
                continue 'outer;
            }
            print!("        ");
        }
        println!("{prefix}{{ C::unimp(a, w, c) }} }}");
    }
    println!("      _ => C::unimp(a, w, c)");
    println!("    }}");
    println!("}}");
    println!();
    generate_enum();
}

#[cfg(test)]
mod test {
    use crate::generated_riscv_decoder::decoder;

    pub struct Tester<'a> {
        pub s: &'a str,
    }

    use crate::riscv_decoding::RiscvDecoder;

    impl RiscvDecoder for Tester<'static> {
        type Context = Self;
        type Returns = usize;

        fn c_unimp(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_unimp";
            0
        }
        fn c_addi4spn(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_addi4spn";
            0
        }
        fn c_fld(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_fld";
            0
        }
        fn c_lw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_lw";
            0
        }
        fn c_ld(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_ld";
            0
        }
        fn c_fsd(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_fsd";
            0
        }
        fn c_sw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_sw";
            0
        }
        fn c_sd(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_sd";
            0
        }
        fn c_nop(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_nop";
            0
        }
        fn c_addi(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_addi";
            0
        }
        fn c_addiw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_addiw";
            0
        }
        fn c_li(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_li";
            0
        }
        fn c_addi16sp(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_addi16sp";
            0
        }
        fn c_lui(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_lui";
            0
        }
        fn c_srli(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_srli";
            0
        }
        fn c_srai(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_srai";
            0
        }
        fn c_andi(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_andi";
            0
        }
        fn c_sub(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_sub";
            0
        }
        fn c_xor(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_xor";
            0
        }
        fn c_or(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_or";
            0
        }
        fn c_and(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_and";
            0
        }
        fn c_subw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_subw";
            0
        }
        fn c_addw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_addw";
            0
        }
        fn c_j(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_j";
            0
        }
        fn c_beqz(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_beqz";
            0
        }
        fn c_bnez(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_bnez";
            0
        }
        fn c_slli(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_slli";
            0
        }
        fn c_fldsp(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_fldsp";
            0
        }
        fn c_lwsp(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_lwsp";
            0
        }
        fn c_ldsp(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_ldsp";
            0
        }
        fn c_jr(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_jr";
            0
        }
        fn c_mv(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_mv";
            0
        }
        fn c_ebreak(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_ebreak";
            0
        }
        fn c_jalr(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_jalr";
            0
        }
        fn c_add(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_add";
            0
        }
        fn c_fsdsp(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_fsdsp";
            0
        }
        fn c_swsp(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_swsp";
            0
        }
        fn c_sdsp(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "c_sdsp";
            0
        }
        fn lui(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "lui";
            0
        }
        fn auipc(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "auipc";
            0
        }
        fn jal(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "jal";
            0
        }
        fn jalr(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "jalr";
            0
        }
        fn beq(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "beq";
            0
        }
        fn bne(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bne";
            0
        }
        fn blt(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "blt";
            0
        }
        fn bge(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bge";
            0
        }
        fn bltu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bltu";
            0
        }
        fn bgeu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bgeu";
            0
        }
        fn lb(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "lb";
            0
        }
        fn lh(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "lh";
            0
        }
        fn lw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "lw";
            0
        }
        fn lbu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "lbu";
            0
        }
        fn lhu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "lhu";
            0
        }
        fn sb(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sb";
            0
        }
        fn sh(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sh";
            0
        }
        fn sw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sw";
            0
        }
        fn addi(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "addi";
            0
        }
        fn slti(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "slti";
            0
        }
        fn sltiu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sltiu";
            0
        }
        fn xori(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "xori";
            0
        }
        fn ori(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "ori";
            0
        }
        fn andi(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "andi";
            0
        }
        fn add(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "add";
            0
        }
        fn sub(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sub";
            0
        }
        fn sll(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sll";
            0
        }
        fn slt(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "slt";
            0
        }
        fn sltu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sltu";
            0
        }
        fn xor(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "xor";
            0
        }
        fn srl(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "srl";
            0
        }
        fn sra(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sra";
            0
        }
        fn or(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "or";
            0
        }
        fn and(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "and";
            0
        }
        fn fence(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fence";
            0
        }
        fn fence_tso(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fence_tso";
            0
        }
        fn ecall(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "ecall";
            0
        }
        fn ebreak(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "ebreak";
            0
        }
        fn lwu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "lwu";
            0
        }
        fn ld(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "ld";
            0
        }
        fn sd(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sd";
            0
        }
        fn slli(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "slli";
            0
        }
        fn srli(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "srli";
            0
        }
        fn srai(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "srai";
            0
        }
        fn addiw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "addiw";
            0
        }
        fn slliw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "slliw";
            0
        }
        fn srliw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "srliw";
            0
        }
        fn sraiw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sraiw";
            0
        }
        fn addw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "addw";
            0
        }
        fn subw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "subw";
            0
        }
        fn sllw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sllw";
            0
        }
        fn srlw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "srlw";
            0
        }
        fn sraw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sraw";
            0
        }
        fn fence_i(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fence_i";
            0
        }
        fn csrrw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "csrrw";
            0
        }
        fn csrrs(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "csrrs";
            0
        }
        fn csrrc(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "csrrc";
            0
        }
        fn csrrwi(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "csrrwi";
            0
        }
        fn csrrsi(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "csrrsi";
            0
        }
        fn csrrci(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "csrrci";
            0
        }
        fn mul(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "mul";
            0
        }
        fn mulh(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "mulh";
            0
        }
        fn mulhsu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "mulhsu";
            0
        }
        fn mulhu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "mulhu";
            0
        }
        fn div(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "div";
            0
        }
        fn divu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "divu";
            0
        }
        fn rem(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "rem";
            0
        }
        fn remu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "remu";
            0
        }
        fn mulw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "mulw";
            0
        }
        fn divw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "divw";
            0
        }
        fn divuw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "divuw";
            0
        }
        fn remw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "remw";
            0
        }
        fn remuw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "remuw";
            0
        }
        fn lr_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "lr_w";
            0
        }
        fn sc_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sc_w";
            0
        }
        fn amoswap_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoswap_w";
            0
        }
        fn amoadd_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoadd_w";
            0
        }
        fn amoxor_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoxor_w";
            0
        }
        fn amoand_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoand_w";
            0
        }
        fn amoor_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoor_w";
            0
        }
        fn amomin_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amomin_w";
            0
        }
        fn amomax_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amomax_w";
            0
        }
        fn amominu_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amominu_w";
            0
        }
        fn amomaxu_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amomaxu_w";
            0
        }
        fn lr_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "lr_d";
            0
        }
        fn sc_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sc_d";
            0
        }
        fn amoswap_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoswap_d";
            0
        }
        fn amoadd_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoadd_d";
            0
        }
        fn amoxor_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoxor_d";
            0
        }
        fn amoand_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoand_d";
            0
        }
        fn amoor_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amoor_d";
            0
        }
        fn amomin_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amomin_d";
            0
        }
        fn amomax_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amomax_d";
            0
        }
        fn amominu_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amominu_d";
            0
        }
        fn amomaxu_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "amomaxu_d";
            0
        }
        fn flw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "flw";
            0
        }
        fn fsw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsw";
            0
        }
        fn fmadd_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmadd_s";
            0
        }
        fn fmsub_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmsub_s";
            0
        }
        fn fnmsub_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fnmsub_s";
            0
        }
        fn fnmadd_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fnmadd_s";
            0
        }
        fn fadd_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fadd_s";
            0
        }
        fn fsub_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsub_s";
            0
        }
        fn fmul_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmul_s";
            0
        }
        fn fdiv_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fdiv_s";
            0
        }
        fn fsqrt_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsqrt_s";
            0
        }
        fn fsgnj_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsgnj_s";
            0
        }
        fn fsgnjn_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsgnjn_s";
            0
        }
        fn fsgnjx_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsgnjx_s";
            0
        }
        fn fmin_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmin_s";
            0
        }
        fn fmax_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmax_s";
            0
        }
        fn fcvt_w_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_w_s";
            0
        }
        fn fcvt_wu_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_wu_s";
            0
        }
        fn fmv_x_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmv_x_w";
            0
        }
        fn feq_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "feq_s";
            0
        }
        fn flt_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "flt_s";
            0
        }
        fn fle_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fle_s";
            0
        }
        fn fclass_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fclass_s";
            0
        }
        fn fcvt_s_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_s_w";
            0
        }
        fn fcvt_s_wu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_s_wu";
            0
        }
        fn fmv_w_x(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmv_w_x";
            0
        }
        fn fcvt_l_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_l_s";
            0
        }
        fn fcvt_lu_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_lu_s";
            0
        }
        fn fcvt_s_l(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_s_l";
            0
        }
        fn fcvt_s_lu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_s_lu";
            0
        }
        fn fld(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fld";
            0
        }
        fn fsd(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsd";
            0
        }
        fn fmadd_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmadd_d";
            0
        }
        fn fmsub_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmsub_d";
            0
        }
        fn fnmsub_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fnmsub_d";
            0
        }
        fn fnmadd_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fnmadd_d";
            0
        }
        fn fadd_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fadd_d";
            0
        }
        fn fsub_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsub_d";
            0
        }
        fn fmul_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmul_d";
            0
        }
        fn fdiv_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fdiv_d";
            0
        }
        fn fsqrt_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsqrt_d";
            0
        }
        fn fsgnj_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsgnj_d";
            0
        }
        fn fsgnjn_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsgnjn_d";
            0
        }
        fn fsgnjx_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fsgnjx_d";
            0
        }
        fn fmin_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmin_d";
            0
        }
        fn fmax_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmax_d";
            0
        }
        fn fcvt_s_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_s_d";
            0
        }
        fn fcvt_d_s(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_d_s";
            0
        }
        fn feq_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "feq_d";
            0
        }
        fn flt_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "flt_d";
            0
        }
        fn fle_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fle_d";
            0
        }
        fn fclass_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fclass_d";
            0
        }
        fn fcvt_w_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_w_d";
            0
        }
        fn fcvt_wu_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_wu_d";
            0
        }
        fn fcvt_d_w(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_d_w";
            0
        }
        fn fcvt_d_wu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_d_wu";
            0
        }
        fn fcvt_l_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_l_d";
            0
        }
        fn fcvt_lu_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_lu_d";
            0
        }
        fn fmv_x_d(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmv_x_d";
            0
        }
        fn fcvt_d_l(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_d_l";
            0
        }
        fn fcvt_d_lu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fcvt_d_lu";
            0
        }
        fn fmv_d_x(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "fmv_d_x";
            0
        }
        fn dret(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "dret";
            0
        }
        fn mret(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "mret";
            0
        }
        fn sret(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sret";
            0
        }
        fn sfence_vma(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sfence_vma";
            0
        }
        fn sinval_vma(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sinval_vma";
            0
        }
        fn sfence_w_inval(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sfence_w_inval";
            0
        }
        fn sfence_inval_ir(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sfence_inval_ir";
            0
        }
        fn wfi(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "wfi";
            0
        }
        fn add_uw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "add_uw";
            0
        }
        fn sh1add(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sh1add";
            0
        }
        fn sh1add_uw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sh1add_uw";
            0
        }
        fn sh2add(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sh2add";
            0
        }
        fn sh2add_uw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sh2add_uw";
            0
        }
        fn sh3add(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sh3add";
            0
        }
        fn sh3add_uw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sh3add_uw";
            0
        }
        fn slli_uw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "slli_uw";
            0
        }
        fn czero_eqz(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "czero_eqz";
            0
        }
        fn czero_nez(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "czero_nez";
            0
        }
        fn andn(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "andn";
            0
        }
        fn orn(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "orn";
            0
        }
        fn xnor(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "xnor";
            0
        }
        fn clz(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "clz";
            0
        }
        fn clzw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "clzw";
            0
        }
        fn ctz(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "ctz";
            0
        }
        fn ctzw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "ctzw";
            0
        }
        fn cpop(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "cpop";
            0
        }
        fn cpopw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "cpopw";
            0
        }
        fn max(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "max";
            0
        }
        fn maxu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "maxu";
            0
        }
        fn min(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "min";
            0
        }
        fn minu(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "minu";
            0
        }
        fn orc_b(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "orc_b";
            0
        }
        fn rev8(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "rev8";
            0
        }
        fn rol(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "rol";
            0
        }
        fn rolw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "rolw";
            0
        }
        fn ror(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "ror";
            0
        }
        fn rori(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "rori";
            0
        }
        fn roriw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "roriw";
            0
        }
        fn rorw(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "rorw";
            0
        }
        fn sext_b(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sext_b";
            0
        }
        fn sext_h(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "sext_h";
            0
        }
        fn zext_h(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "zext_h";
            0
        }
        fn bclr(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bclr";
            0
        }
        fn bclri(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bclri";
            0
        }
        fn bext(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bext";
            0
        }
        fn bexti(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bexti";
            0
        }
        fn binv(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "binv";
            0
        }
        fn binvi(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "binvi";
            0
        }
        fn bset(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bset";
            0
        }
        fn bseti(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "bseti";
            0
        }
        fn clmul(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "clmul";
            0
        }
        fn clmulh(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "clmulh";
            0
        }
        fn clmulr(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "clmulr";
            0
        }
        fn unimp(_a: u64, _w: u32, s: &mut Self::Context) -> usize {
            s.s = "unimp";
            0
        }
    }

    #[ignore]
    #[test]
    // Note, takes 2m30s on my Mac Mini M4 Pro
    pub fn try_this() {
        let mut tester = Tester { s: "" };

        'outer: for w in 0..=!0 {
            if w & 0xFFFFF == 0xFFFFF {
                eprint!("{w:08x}\r");
            }
            decoder(0x1234, w, &mut tester);
            for (m, p, n) in &super::INSTRUCTIONS {
                if (m & w) == *p {
                    let n = n.replace('.', "_");
                    assert_eq!(
                        tester.s, n,
                        "Uh on, {w:08x} should decode as {n}, but got {}",
                        tester.s
                    );
                    continue 'outer;
                }
            }

            assert_eq!(
                tester.s, "unimp",
                "Uh on, {w:08x} should decode as unimp, but got {}",
                tester.s
            );

            //println!("{w:08x} {}", tester.s);
        }
    }
}

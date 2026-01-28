use simmerv::riscv_insns::generate_riscv_decoder;

fn main() -> anyhow::Result<()> {
    generate_riscv_decoder();

    Ok(())
}

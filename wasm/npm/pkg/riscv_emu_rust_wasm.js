import * as wasm from "./riscv_emu_rust_wasm_bg.wasm";
export * from "./riscv_emu_rust_wasm_bg.js";
import { __wbg_set_wasm } from "./riscv_emu_rust_wasm_bg.js";
__wbg_set_wasm(wasm);
wasm.__wbindgen_start();

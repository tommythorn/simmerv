cargo install wasm-bindgen-cli
wasm-pack build
wasm-bindgen ../target/wasm32-unknown-unknown/release/riscv_emu_rust_wasm.wasm --out-dir ./web --target web --no-typescript

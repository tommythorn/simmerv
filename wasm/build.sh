set -e

cargo install --locked wasm-pack
cargo install -f wasm-bindgen-cli --version 0.2.108
wasm-pack build
wasm-bindgen ../target/wasm32-unknown-unknown/release/simmerv_wasm.wasm --out-dir ./web --target web --no-typescript

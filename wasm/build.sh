# cargo install --locked wasm-pack wasm-bindgen-cli
# 20260326 this seems to cause problems now and I had to use
cargo install --locked wasm-pack
cargo install -f wasm-bindgen-cli --version 0.2.114
wasm-pack build
wasm-bindgen ../target/wasm32-unknown-unknown/release/simmerv_wasm.wasm --out-dir ./web --target web --no-typescript

cargo install wasm-bindgen-cli
wasm-pack build
wasm-bindgen ../target/wasm32-unknown-unknown/release/simmerv_wasm.wasm --out-dir ./web --target web --no-typescript

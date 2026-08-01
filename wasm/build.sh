#!/bin/sh
#
# Build the WebAssembly demo into ./web.
#
# ./web is the GitHub Pages site root and is published by
# .github/workflows/pages.yml on every push to main, so the two generated files
# (simmerv_wasm.js, simmerv_wasm_bg.wasm) are NOT checked in -- see .gitignore.
# Everything else in ./web is hand-written or vendored.

set -e

# wasm-bindgen-cli must match the wasm-bindgen crate that wasm-pack links in,
# or the generated glue rejects the module at load time. Keep this in step with
# the version resolved in Cargo.lock.
BINDGEN_VER=0.2.126

# `cargo install` takes minutes; skip it when the tool is already there at the
# right version, so a warm cache (CI) or a repeat local build is instant.
command -v wasm-pack >/dev/null 2>&1 || cargo install --locked wasm-pack
case " $(wasm-bindgen --version 2>/dev/null) " in
	*" $BINDGEN_VER "*) ;;
	*) cargo install -f wasm-bindgen-cli --version "$BINDGEN_VER" ;;
esac

wasm-pack build
wasm-bindgen ../target/wasm32-unknown-unknown/release/simmerv_wasm.wasm \
	--out-dir ./web --target web --no-typescript

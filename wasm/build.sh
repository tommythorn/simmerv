#!/bin/sh
#
# Build the WebAssembly demo into ./web.
#
# ./web is the GitHub Pages site root and is published by
# .github/workflows/pages.yml on every push to main, so the two generated files
# (simmerv_wasm.js, simmerv_wasm_bg.wasm) are NOT checked in -- see .gitignore.
# Everything else in ./web is hand-written or vendored.

set -e

# One wasm-pack invocation runs cargo, wasm-bindgen and wasm-opt as a pipeline,
# and --target web emits exactly the two files index.html imports.
#
# This used to build for bundlers and then re-run wasm-bindgen by hand on the
# raw target/ output. That second pass bypassed wasm-opt, so ./web shipped the
# unoptimized binary while the optimized one sat unused in pkg/. It also meant
# pinning wasm-bindgen-cli to whatever wasm-bindgen the crate graph resolved to,
# which drifted and broke CI more than once; wasm-pack picks a matching
# wasm-bindgen itself, so that pin is gone with it.
#
# Build into pkg/ (gitignored) rather than straight to web/: wasm-pack also
# writes .gitignore and LICENSE into its out-dir, and web/ holds hand-written
# files -- index.html, App.js, README.md, xtermjs/ -- to leave alone.
command -v wasm-pack >/dev/null 2>&1 || cargo install --locked wasm-pack

rm -rf pkg
wasm-pack build --target web --out-dir pkg --no-typescript --no-pack

cp pkg/simmerv_wasm.js pkg/simmerv_wasm_bg.wasm web/

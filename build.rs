fn main() {
    // Only compile the vmnet shim when building for macOS.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/vmnet_shim.c")
            .compile("vmnet_shim");
        println!("cargo:rustc-link-lib=framework=vmnet");
    }
}

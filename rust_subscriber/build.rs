fn main() {
    // Instruct rustc to pass a linker version script only when building our cdylib
    println!("cargo:rustc-link-arg=-Wl,--version-script=exports.map");
}



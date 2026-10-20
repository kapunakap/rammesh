fn main() {
    assert_eq!(
        std::env::var("CARGO_CFG_TARGET_OS").unwrap(),
        "macos",
        "This donor is implemented for macOS"
    );
    cc::Build::new()
        .file("src/macos.c")
        .warnings(true)
        .compile("rammesh_macos");
    println!("cargo:rerun-if-changed=src/macos.c");
}

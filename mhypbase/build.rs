fn main() {
    println!(
        "cargo:rustc-link-search=native={}",
        std::env::var("OUT_DIR").unwrap()
    );
    println!("cargo:rustc-link-arg=/DEF:mhypbase.def");
}

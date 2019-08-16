fn main() {
    let dst = cmake::build("../../libunwind");

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=unwind");
}

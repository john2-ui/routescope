use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/routescope_tc.c");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest_dir.join("src/routescope_tc.c");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("routescope_tc.o");
    let clang = env::var("ROUTESCOPE_CLANG").unwrap_or_else(|_| "clang".to_owned());

    let status = Command::new(&clang)
        .args(["-target", "bpf", "-D__TARGET_ARCH_x86", "-O2", "-g", "-c"])
        .arg(&source)
        .args(["-o"])
        .arg(&output)
        .status()
        .unwrap_or_else(|error| panic!("failed to execute {clang}: {error}"));

    if !status.success() {
        panic!("clang failed to compile {}", source.display());
    }
}

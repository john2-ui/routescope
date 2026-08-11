use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/routescope_tc.c");
    println!("cargo:rerun-if-env-changed=ROUTESCOPE_BPF_TARGET_ARCH");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest_dir.join("src/routescope_tc.c");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("routescope_tc.o");
    let clang = env::var("ROUTESCOPE_CLANG").unwrap_or_else(|_| "clang".to_owned());
    let target_arch = env::var("ROUTESCOPE_BPF_TARGET_ARCH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_lowercase())
        .unwrap_or_else(|| {
            env::var("CARGO_CFG_TARGET_ARCH")
                .ok()
                .map(|value| default_bpf_arch(&value).to_owned())
                .unwrap_or_else(|| "x86".to_owned())
        });
    if !is_supported_bpf_arch(&target_arch) {
        panic!(
            "unsupported ROUTESCOPE_BPF_TARGET_ARCH={target_arch}; \
             expected x86, arm64, arm, mips, mips64, ppc64, s390, or riscv64"
        );
    }
    let target_define = format!("-D__TARGET_ARCH_{target_arch}");

    let status = Command::new(&clang)
        .args(["-target", "bpf", &target_define, "-O2", "-g", "-c"])
        .arg(&source)
        .args(["-o"])
        .arg(&output)
        .status()
        .unwrap_or_else(|error| panic!("failed to execute {clang}: {error}"));

    if !status.success() {
        panic!("clang failed to compile {}", source.display());
    }
}

fn default_bpf_arch(target_arch: &str) -> &'static str {
    match target_arch {
        "x86" | "x86_64" => "x86",
        "arm" => "arm",
        "aarch64" => "arm64",
        "mips" => "mips",
        "mips64" => "mips64",
        "powerpc64" => "ppc64",
        "s390x" => "s390",
        "riscv64" => "riscv64",
        _ => "x86",
    }
}

fn is_supported_bpf_arch(target_arch: &str) -> bool {
    matches!(
        target_arch,
        "x86" | "arm64" | "arm" | "mips" | "mips64" | "ppc64" | "s390" | "riscv64"
    )
}

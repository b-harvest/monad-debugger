use std::{env, fs, path::PathBuf};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let metadata = aya_build::cargo_metadata::MetadataCommand::new()
        .manifest_path("../ebpf/Cargo.toml")
        .exec()
        .expect("failed to fetch cargo metadata for eBPF crate");

    let packages = metadata
        .packages
        .into_iter()
        .filter(|pkg| pkg.name == "monad-debugger-ebpf")
        .collect::<Vec<_>>();

    aya_build::build_ebpf(packages).expect("failed to build eBPF programs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let src = out_dir.join("monad-debugger-ebpf");
    let dst = out_dir.join("monad-debugger-ebpf.bpf.o");

    fs::copy(&src, &dst).unwrap_or_else(|e| panic!("failed to copy {src:?} to {dst:?}: {e}"));

    println!("cargo:rerun-if-changed=../ebpf/src");
}

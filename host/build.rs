fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
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

    println!("cargo:rerun-if-changed=../ebpf/src");
}

use std::{
    env, fs,
    path::{Path, PathBuf},
};

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
    let build_root = out_dir.join("monad-debugger-ebpf");

    let elf_path = find_elf(&build_root)
        .unwrap_or_else(|| panic!("failed to locate built eBPF object under {build_root:?}"));
    let dst = out_dir.join("monad-debugger-ebpf.bpf.o");

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).expect("failed to create output directory");
    }

    fs::copy(&elf_path, &dst)
        .unwrap_or_else(|e| panic!("failed to copy {elf_path:?} to {dst:?}: {e}"));

    println!("cargo:warning=using eBPF object {:?}", elf_path);
    println!("cargo:rerun-if-changed=../ebpf/src");
}

fn find_elf(root: &Path) -> Option<PathBuf> {
    if !root.exists() {
        return None;
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && is_elf_name(path.file_name()) {
                return Some(path);
            } else if path.is_dir() {
                stack.push(path);
            }
        }
    }

    None
}

fn is_elf_name(name: Option<&std::ffi::OsStr>) -> bool {
    match name.and_then(|s| s.to_str()) {
        Some("monad-debugger-ebpf") => true,
        Some(s) if s.starts_with("monad-debugger-ebpf.") => true,
        _ => false,
    }
}

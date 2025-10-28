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
    let build_root = out_dir.join("monad-debugger-ebpf");

    let elf_path = locate_elf(&build_root)
        .unwrap_or_else(|| panic!("failed to locate built eBPF object under {build_root:?}"));
    let dst = out_dir.join("monad-debugger-ebpf.bpf.o");

    fs::copy(&elf_path, &dst)
        .unwrap_or_else(|e| panic!("failed to copy {elf_path:?} to {dst:?}: {e}"));

    println!("cargo:rerun-if-changed=../ebpf/src");
}

fn locate_elf(root: &PathBuf) -> Option<PathBuf> {
    if !root.exists() {
        return None;
    }

    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let ty = match entry.file_type() {
                Ok(ty) => ty,
                Err(_) => continue,
            };

            if ty.is_file() && is_matching_file(&path) {
                if let Ok(meta) = path.metadata() {
                    if meta.len() > 0 {
                        return Some(path);
                    }
                }
            } else if ty.is_dir() {
                stack.push(path);
            }
        }
    }

    None
}

fn is_matching_file(path: &PathBuf) -> bool {
    match path.file_name() {
        Some(name) => {
            let name = name.to_string_lossy();
            name == "monad-debugger-ebpf" || name.starts_with("monad-debugger-ebpf.")
        }
        None => false,
    }
}

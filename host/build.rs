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

    let mut elf_path: Option<PathBuf> = None;
    if build_root.is_dir() {
        let mut stack = vec![build_root.clone()];
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(err) => panic!("failed to read directory {dir:?}: {err}"),
            };

            for entry in entries {
                let entry = entry.expect("invalid dir entry");
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name() == Some(std::ffi::OsStr::new("monad-debugger-ebpf")) {
                    elf_path = Some(path);
                    break;
                }
            }

            if elf_path.is_some() {
                break;
            }
        }
    }

    let elf_path = elf_path
        .unwrap_or_else(|| panic!("failed to locate built eBPF object under {build_root:?}"));
    let dst = out_dir.join("monad-debugger-ebpf.bpf.o");

    fs::copy(&elf_path, &dst)
        .unwrap_or_else(|e| panic!("failed to copy {elf_path:?} to {dst:?}: {e}"));

    println!("cargo:rerun-if-changed=../ebpf/src");
}

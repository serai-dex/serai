fn main() {
  use std::{path::PathBuf, fs, env, process::Command};

  // Prevent recursing infinitely
  if env::var("TARGET").unwrap() == "wasm32v1-none" {
    return;
  }

  // https://github.com/rust-lang/rust/issues/145491
  const ONE_45491: &str =
    "-C link-arg=--mllvm=-mcpu=mvp -C link-arg=--mllvm=-mattr=+mutable-globals";
  const WASM: &str = "-C link-arg=--export-table";
  const REQUIRED_BY_SUBSTRATE: &str = "--cfg substrate_runtime";
  const SAFETY: &str = "-C overflow-checks=true -C panic=abort";
  // `symbol-mangling-version` is defined to provide an explicit, canonical definition of symbols.
  // `embed-bitcode=false` is set as the bitcode is unnecessary yet takes notable time to compile.
  /*
    Rust's LTO requires bitcode, forcing us to defer to the linker's LTO. While this would suggest
    we _should_ set `embed-bitcode=true`, Rust's documentation suggests that's likely not desired
    and should solely be done when compiling one library with mixed methods of linking. When
    compiling and linking just once (as seen here), it's suggested to use the linker's LTO instead.

    https://doc.rust-lang.org/1.91.1/rustc/codegen-options/index.html#embed-bitcode
  */
  const COMPILATION: &str =
    "-C symbol-mangling-version=v0 -C embed-bitcode=false -C linker-plugin-lto=true";

  let profile = env::var("PROFILE").unwrap();
  let mut env = vec![];
  let release = profile == "release";
  let mut rustflags = format!("{ONE_45491} {WASM} {REQUIRED_BY_SUBSTRATE} {SAFETY} {COMPILATION}");
  if release {
    rustflags.push_str(" -C debug-assertions=false -C codegen-units=1 -C opt-level=3");
    // Strip debug info, as we have debug builds for that
    rustflags.push_str(" -C debuginfo=none -C strip=symbols");
    // `incremental` is recommended to be disabled for release builds, and this should
    // be a clean build used just once as part of the reproducible build process.
    env.push(("CARGO_INCREMENTAL", "false"));
  }

  let target_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("target");

  let cargo_command = || {
    let cargo = env::var("CARGO").unwrap();
    let mut command = Command::new(&cargo);
    command
      .current_dir(env::var("CARGO_MANIFEST_DIR").unwrap())
      .env_clear()
      .env("PATH", env::var("PATH").unwrap())
      .env("CARGO", cargo)
      .env("RUSTC", env::var("RUSTC").unwrap())
      .env("RUSTFLAGS", &rustflags)
      .env("CARGO_TARGET_DIR", &target_dir);
    for (key, value) in &env {
      command.env(key, value);
    }
    command
  };

  let workspace = {
    let workspace = cargo_command()
      .arg("locate-project")
      .arg("--workspace")
      .arg("--message-format")
      .arg("plain")
      .output()
      .unwrap();
    assert!(workspace.status.success());
    let mut workspace = PathBuf::from(String::from_utf8(workspace.stdout).unwrap().trim());
    assert_eq!(workspace.file_name().unwrap(), "Cargo.toml");
    assert!(workspace.pop());
    workspace
  };

  // Re-run anytime the workspace changes
  // TODO: Re-run anytime `Cargo.lock` or specifically the `src` folders change
  println!("cargo::rerun-if-changed={}", workspace.display());

  let mut command = cargo_command();
  command
    .arg("rustc")
    .arg("--package")
    .arg(env::var("CARGO_PKG_NAME").unwrap())
    .arg("--target")
    .arg("wasm32v1-none")
    .arg("--crate-type")
    .arg("cdylib")
    .arg("--no-default-features");
  if release {
    command.arg("--release");
  }
  assert!(command.status().unwrap().success());

  // Place the resulting WASM blob into the parent `target` directory
  {
    let wasm_file = env::var("CARGO_PKG_NAME").unwrap().replace('-', "_") + ".wasm";
    let src_file = target_dir.join("wasm32v1-none").join(&profile).join(&wasm_file);
    let dst_file = {
      // TODO: This sets `dst_dir` to the default target directory, not the actual
      let mut dst_dir = workspace.clone();
      // e.g. workspace/target/debug
      dst_dir.extend(["target", &profile]);
      let _ = fs::create_dir_all(&dst_dir);
      // e.g. workspace/target/debug/serai_runtime.wasm
      dst_dir.join(&wasm_file)
    };
    fs::copy(&src_file, &dst_file).unwrap();
  }
}

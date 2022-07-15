use std::{env, path::Path, process::Command};

fn main() {
  if !Command::new("git")
    .args(&["submodule", "update", "--init", "--recursive"])
    .status()
    .unwrap()
    .success()
  {
    panic!("git failed to init submodules");
  }

  if !Command::new("mkdir")
    .args(&["-p", ".build"])
    .current_dir(&Path::new("c"))
    .status()
    .unwrap()
    .success()
  {
    panic!("failed to create a directory to track build progress");
  }

  let out_dir = &env::var("OUT_DIR").unwrap();

  // Use a file to signal if Monero was already built, as that should never be rebuilt
  // If the signaling file was deleted, run this script again to rebuild Monero though
  println!("cargo:rerun-if-changed=c/.build/monero");
  if !Path::new("c/.build/monero").exists() {
    if !Command::new("make")
      .arg(format!("-j{}", &env::var("THREADS").unwrap_or("2".to_string())))
      .current_dir(&Path::new("c/monero"))
      .status()
      .unwrap()
      .success()
    {
      panic!("make failed to build Monero. Please check your dependencies");
    }

    if !Command::new("touch")
      .arg("monero")
      .current_dir(&Path::new("c/.build"))
      .status()
      .unwrap()
      .success()
    {
      panic!("failed to create a file to label Monero as built");
    }
  }

  println!("cargo:rerun-if-changed=c/wrapper.cpp");
  #[rustfmt::skip]
  cc::Build::new()
    .static_flag(true)
    .warnings(false)
    .extra_warnings(false)
    .flag("-Wno-deprecated-declarations")

    .include("c/monero/external/supercop/include")
    .include("c/monero/contrib/epee/include")
    .include("c/monero/src")
    .include("c/monero/build/release/generated_include")

    .define("AUTO_INITIALIZE_EASYLOGGINGPP", None)
    .include("c/monero/external/easylogging++")
    .file("c/monero/external/easylogging++/easylogging++.cc")

    .file("c/monero/src/common/aligned.c")
    .file("c/monero/src/common/perf_timer.cpp")

    .include("c/monero/src/crypto")
    .file("c/monero/src/crypto/crypto-ops-data.c")
    .file("c/monero/src/crypto/crypto-ops.c")
    .file("c/monero/src/crypto/keccak.c")
    .file("c/monero/src/crypto/hash.c")

    .include("c/monero/src/device")
    .file("c/monero/src/device/device_default.cpp")

    .include("c/monero/src/ringct")
    .file("c/monero/src/ringct/rctCryptoOps.c")
    .file("c/monero/src/ringct/rctTypes.cpp")
    .file("c/monero/src/ringct/rctOps.cpp")
    .file("c/monero/src/ringct/multiexp.cc")
    .file("c/monero/src/ringct/bulletproofs.cc")
    .file("c/monero/src/ringct/rctSigs.cpp")

    .file("c/wrapper.cpp")
    .compile("wrapper");

  println!("cargo:rustc-link-search={}", out_dir);
  println!("cargo:rustc-link-lib=wrapper");
  println!("cargo:rustc-link-lib=stdc++");
}

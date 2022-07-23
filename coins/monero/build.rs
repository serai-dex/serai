use std::process::Command;

fn main() {
  if !Command::new("git")
    .args(&["submodule", "update", "--init", "--recursive"])
    .status()
    .unwrap()
    .success()
  {
    panic!("git failed to init submodules");
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

    .include("c/monero/src/ringct")
    .file("c/monero/src/ringct/rctCryptoOps.c")
    .file("c/monero/src/ringct/rctTypes.cpp")
    .file("c/monero/src/ringct/rctOps.cpp")
    .file("c/monero/src/ringct/multiexp.cc")
    .file("c/monero/src/ringct/bulletproofs.cc")
    .file("c/monero/src/ringct/rctSigs.cpp")

    .file("c/wrapper.cpp")
    .compile("wrapper");

  println!("cargo:rustc-link-lib=wrapper");
  println!("cargo:rustc-link-lib=stdc++");
}

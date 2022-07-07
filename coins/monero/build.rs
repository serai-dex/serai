use std::{env, path::Path, process::Command};

fn main() {
  if !Command::new("git").args(&["submodule", "update", "--init", "--recursive"]).status().unwrap().success() {
    panic!("git failed to init submodules");
  }

  if !Command ::new("mkdir").args(&["-p", ".build"])
    .current_dir(&Path::new("c")).status().unwrap().success() {
      panic!("failed to create a directory to track build progress");
  }

  let out_dir = &env::var("OUT_DIR").unwrap();

  // Use a file to signal if Monero was already built, as that should never be rebuilt
  // If the signaling file was deleted, run this script again to rebuild Monero though
  // TODO: Move this signaling file into OUT_DIR once Monero is built statically successfully
  println!("cargo:rerun-if-changed=c/.build/monero");
  if !Path::new("c/.build/monero").exists() {
    if !Command::new("make").arg(format!("-j{}", &env::var("THREADS").unwrap_or("2".to_string())))
      .current_dir(&Path::new("c/monero")).status().unwrap().success() {
        panic!("make failed to build Monero. Please check your dependencies");
    }

    if !Command::new("touch").arg("monero")
      .current_dir(&Path::new("c/.build")).status().unwrap().success() {
        panic!("failed to create a file to label Monero as built");
    }
  }

 println!("cargo:rerun-if-env-changed=OUT_DIR");
 if !Path::new(
    &format!(
      "{}/{}cncrypto.{}",
      out_dir,
      &env::consts::DLL_PREFIX,
      &env::consts::DLL_EXTENSION
    )
  ).exists() {
    let mut paths = vec![
      "c/monero/build/release/contrib/epee/src/libepee.a".to_string(),
      "c/monero/build/release/external/easylogging++/libeasylogging.a".to_string(),
      "c/monero/build/release/external/randomx/librandomx.a".to_string()
    ];

    for (folder, lib) in [
      ("common", "common"),
      ("crypto", "cncrypto"),
      ("crypto/wallet", "wallet-crypto"),
      ("cryptonote_basic", "cryptonote_basic"),
      ("cryptonote_basic", "cryptonote_format_utils_basic"),
      ("", "version"),
      ("device", "device"),
      ("ringct", "ringct_basic"),
      ("ringct", "ringct")
    ] {
      paths.push(
        format!(
          "c/monero/build/release/src/{}/{}{}.a",
          folder,
          &env::consts::DLL_PREFIX,
          lib
        )
      );
    }

    for path in paths {
      if !Command::new("cp").args(&[&path, out_dir]).status().unwrap().success() {
        panic!("Failed to cp {}", path);
      }
    }
  }

  println!("cargo:rerun-if-changed=c/wrapper.cpp");
  if !Path::new(&format!("{}/{}wrapper.a", out_dir, &env::consts::DLL_PREFIX)).exists() {
    cc::Build::new()
      .file("c/wrapper.cpp")
      .cpp(true)
      .warnings(false)
      .include("c/monero/contrib/epee/include")
      .include("c/monero/src")
      .compile("wrapper");
  }

  println!("cargo:rustc-link-search={}", out_dir);
  println!("cargo:rustc-link-lib=wrapper");
  println!("cargo:rustc-link-lib=ringct");
  println!("cargo:rustc-link-lib=ringct_basic");
  println!("cargo:rustc-link-lib=device");
  println!("cargo:rustc-link-lib=cryptonote_basic");
  println!("cargo:rustc-link-lib=cncrypto");
  println!("cargo:rustc-link-lib=cryptonote_format_utils_basic");
  println!("cargo:rustc-link-lib=version");
  println!("cargo:rustc-link-lib=wallet-crypto");
  println!("cargo:rustc-link-lib=easylogging");
  println!("cargo:rustc-link-lib=epee");
  println!("cargo:rustc-link-lib=common");
  println!("cargo:rustc-link-lib=randomx");
  println!("cargo:rustc-link-lib=unbound");
  println!("cargo:rustc-link-lib=sodium");
  println!("cargo:rustc-link-lib=boost_system");
  println!("cargo:rustc-link-lib=boost_thread");
  println!("cargo:rustc-link-lib=boost_filesystem");
  println!("cargo:rustc-link-lib=hidapi-hidraw");
  println!("cargo:rustc-link-lib=stdc++");

  println!("cargo:rustc-link-arg=-zmuldefs");
}

use std::process::Command;
use std::env;
use std::path::Path;

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
    if !Command::new("cmake").args(&["cmake", "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=1", "."])
      .current_dir(&Path::new("c/monero")).status().unwrap().success() {
        panic!("cmake failed to generate Monero's build scripts");
    }

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
      "c/monero/src/crypto/{}cncrypto.{}",
      &env::consts::DLL_PREFIX,
      &env::consts::DLL_EXTENSION
    )
  ).exists() {
    if !Command::new("cp").args(&[
      &format!(
        "c/monero/src/crypto/{}cncrypto.{}",
        &env::consts::DLL_PREFIX,
        &env::consts::DLL_EXTENSION
      ),
      out_dir
    ]).status().unwrap().success() {
      panic!("Failed to cp cncrypto");
    }

    if !Command::new("cp").args(&[
      &format!(
        "c/monero/src/device/{}device.{}",
        &env::consts::DLL_PREFIX,
        &env::consts::DLL_EXTENSION
      ),
      out_dir
    ]).status().unwrap().success() {
      panic!("Failed to cp device");
    }

    if !Command::new("cp").args(&[
      &format!(
        "c/monero/src/ringct/{}ringct_basic.{}",
        &env::consts::DLL_PREFIX,
        &env::consts::DLL_EXTENSION
      ),
      out_dir
    ]).status().unwrap().success() {
      panic!("Failed to cp ringct_basic");
    }

    if !Command::new("cp").args(&[
      &format!(
        "c/monero/src/ringct/{}ringct.{}",
        &env::consts::DLL_PREFIX,
        &env::consts::DLL_EXTENSION
      ),
      out_dir
    ]).status().unwrap().success() {
      panic!("Failed to cp ringct");
    }

    println!("cargo:rerun-if-changed=c/wrapper.c");
    if !Command::new("g++").args(&[
      "-O3", "-Wall", "-shared", "-std=c++14", "-fPIC",
      "-Imonero/contrib/epee/include", "-Imonero/src",
      "wrapper.c", "-o", &format!(
        "{}/{}wrapper.{}",
        out_dir,
        &env::consts::DLL_PREFIX,
        &env::consts::DLL_EXTENSION
      ),
      &format!("-L{}", out_dir),
      "-ldevice", "-lringct_basic", "-lringct"
    ]).current_dir(&Path::new("c")).status().unwrap().success() {
      panic!("g++ failed to build the wrapper");
    }
  }

  println!("cargo:rustc-link-search={}", out_dir);
  println!("cargo:rustc-link-lib=cncrypto");
  println!("cargo:rustc-link-lib=device");
  println!("cargo:rustc-link-lib=ringct_basic");
  println!("cargo:rustc-link-lib=ringct");
  println!("cargo:rustc-link-lib=wrapper");
}

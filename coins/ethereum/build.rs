use std::process::Command;

use ethers_contract::Abigen;

fn main() {
  println!("cargo:rerun-if-changed=contracts/*");
  println!("cargo:rerun-if-changed=artifacts/*");

  for line in String::from_utf8(Command::new("solc").args(["--version"]).output().unwrap().stdout)
    .unwrap()
    .lines()
  {
    if let Some(version) = line.strip_prefix("Version: ") {
      let version = version.split('+').next().unwrap();
      assert_eq!(version, "0.8.25");
    }
  }

  #[rustfmt::skip]
  let args = [
    "--base-path", ".",
    "-o", "./artifacts", "--overwrite",
    "--bin", "--abi",
    "--optimize",
    "./contracts/Schnorr.sol", "./contracts/Router.sol",
  ];
  assert!(Command::new("solc").args(args).status().unwrap().success());

  Abigen::new("Schnorr", "./artifacts/Schnorr.abi")
    .unwrap()
    .generate()
    .unwrap()
    .write_to_file("./src/abi/schnorr.rs")
    .unwrap();

  Abigen::new("Router", "./artifacts/Router.abi")
    .unwrap()
    .generate()
    .unwrap()
    .write_to_file("./src/abi/router.rs")
    .unwrap();
}

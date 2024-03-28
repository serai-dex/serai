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
    "--via-ir", "--optimize",

    "./contracts/IERC20.sol",

    "./contracts/Schnorr.sol",
    "./contracts/Deployer.sol",
    "./contracts/Sandbox.sol",
    "./contracts/Router.sol",

    "./src/tests/contracts/Schnorr.sol",
    "./src/tests/contracts/ERC20.sol",

    "--no-color",
  ];
  let solc = Command::new("solc").args(args).output().unwrap();
  assert!(solc.status.success());
  for line in String::from_utf8(solc.stderr).unwrap().lines() {
    assert!(!line.starts_with("Error:"));
  }

  Abigen::new("Deployer", "./artifacts/Deployer.abi")
    .unwrap()
    .generate()
    .unwrap()
    .write_to_file("./src/abi/deployer.rs")
    .unwrap();

  Abigen::new("Router", "./artifacts/Router.abi")
    .unwrap()
    .generate()
    .unwrap()
    .write_to_file("./src/abi/router.rs")
    .unwrap();

  Abigen::new("ERC20", "./artifacts/IERC20.abi")
    .unwrap()
    .generate()
    .unwrap()
    .write_to_file("./src/abi/erc20.rs")
    .unwrap();

  Abigen::new("TestSchnorr", "./artifacts/TestSchnorr.abi")
    .unwrap()
    .generate()
    .unwrap()
    .write_to_file("./src/tests/abi/schnorr.rs")
    .unwrap();
}

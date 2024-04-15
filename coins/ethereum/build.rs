use std::{fs, process::Command};

use alloy_sol_macro_input::SolInputExpander;
use alloy_sol_macro::SolMacroExpander;

fn abi_to_file(name: &'static str, abi: &'static str, file: &str) {
  let input = syn::parse_str(&(name.to_string() + ", r#\"" + abi + "\"#")).unwrap();
  let tokens = SolMacroExpander.expand(&input).unwrap();
  let code = prettyplease::unparse(&syn::parse2::<syn::File>(tokens).unwrap());
  fs::write(file, code).unwrap();
}

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

  abi_to_file("Deployer", include_str!("./artifacts/Deployer.abi"), "./src/abi/deployer.rs");
  abi_to_file("Router", include_str!("./artifacts/Router.abi"), "./src/abi/router.rs");
  abi_to_file("ERC20", include_str!("./artifacts/IERC20.abi"), "./src/abi/erc20.rs");
  abi_to_file(
    "TestSchnorr",
    include_str!("./artifacts/TestSchnorr.abi"),
    "./src/tests/abi/schnorr.rs",
  );
}

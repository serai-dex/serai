use std::process::Command;

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

    "./contracts/tests/Schnorr.sol",
    "./contracts/tests/ERC20.sol",

    "--no-color",
  ];
  let solc = Command::new("solc").args(args).output().unwrap();
  assert!(solc.status.success());
  let stderr = String::from_utf8(solc.stderr).unwrap();
  for line in stderr.lines() {
    if line.contains("Error:") {
      println!("{stderr}");
      panic!()
    }
  }
}

fn main() {
  println!("cargo:rerun-if-changed=contracts");
  println!("cargo:rerun-if-changed=artifacts");

  #[rustfmt::skip]
  let args = [
    "--base-path", ".",
    "-o", "./artifacts", "--overwrite",
    "--bin", "--abi",
    "--optimize",
    "./contracts/Schnorr.sol"
  ];

  assert!(std::process::Command::new("solc").args(args).status().unwrap().success());
}

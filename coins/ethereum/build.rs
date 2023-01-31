use ethers_solc::{Project, ProjectPathsConfig};
use ethers::contract::Abigen;

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

  //assert!(std::process::Command::new("solc").args(args).status().unwrap().success());

  // Tell Cargo that if a source file changes, to rerun this build script.
  project.rerun_if_sources_changed();

  Abigen::new("Router", format!("./artifacts/Router.sol/Router.json"))
    .unwrap()
    .generate()
    .unwrap()
    .write_to_file(format!("./src/router.rs"))
    .unwrap();
}

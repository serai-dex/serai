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


  Abigen::new("Router", "./artifacts/Router.sol/Router.json")
    .unwrap()
    .generate()
    .unwrap()
    .write_to_file("./src/router.rs")
    .unwrap();
}

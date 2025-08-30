fn main() {
  let artifacts_path =
    std::env::var("OUT_DIR").unwrap().clone() + "/serai-processor-ethereum-deployer";
  build_solidity_contracts::build(&[], "contracts", &artifacts_path).unwrap();
}

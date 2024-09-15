fn main() {
  let artifacts_path = std::env::var("OUT_DIR").unwrap().to_string() + "/ethereum-schnorr-contract";
  build_solidity_contracts::build(&[], "contracts", &artifacts_path).unwrap();
}

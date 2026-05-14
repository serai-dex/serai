fn main() {
  #[expect(clippy::disallowed_methods)]
  let artifacts_path = std::env::var("OUT_DIR").unwrap().clone() + "/ethereum-schnorr-contract";
  build_solidity_contracts::build(&[], "contracts", &artifacts_path).unwrap();
}

fn main() {
  build_solidity_contracts::build(
    &["../../../networks/ethereum/schnorr/contracts"],
    "contracts",
    "artifacts",
  )
  .unwrap();
}

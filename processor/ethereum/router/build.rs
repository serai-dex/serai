use std::{env, fs};

use alloy_sol_macro_input::SolInputKind;

fn write(sol: syn_solidity::File, file: &str) {
  let sol = alloy_sol_macro_expander::expand::expand(sol).unwrap();
  fs::write(file, sol.to_string()).unwrap();
}

fn sol(sol_files: &[&str], file: &str) {
  let mut sol = String::new();
  for sol_file in sol_files {
    sol += &fs::read_to_string(sol_file).unwrap();
  }
  let SolInputKind::Sol(sol) = syn::parse_str(&sol).unwrap() else {
    panic!("parsed .sols file wasn't SolInputKind::Sol");
  };
  write(sol, file);
}

fn main() {
  let artifacts_path =
    env::var("OUT_DIR").unwrap().to_string() + "/serai-processor-ethereum-router";

  if !fs::exists(&artifacts_path).unwrap() {
    fs::create_dir(&artifacts_path).unwrap();
  }

  build_solidity_contracts::build(
    &["../../../networks/ethereum/schnorr/contracts", "../erc20/contracts", "contracts"],
    "contracts",
    &artifacts_path,
  )
  .unwrap();
  // These are detected multiple times and distinguished, hence their renaming to canonical forms
  let router_bin = artifacts_path.clone() + "/Router.bin";
  let _ = fs::remove_file(&router_bin); // Remove the file if it already exists, if we can
  fs::rename(artifacts_path.clone() + "/Router_sol_Router.bin", &router_bin).unwrap();

  let router_bin_runtime = artifacts_path.clone() + "/Router.bin-runtime";
  let _ = fs::remove_file(&router_bin_runtime);
  fs::rename(artifacts_path.clone() + "/Router_sol_Router.bin-runtime", router_bin_runtime)
    .unwrap();

  // This cannot be handled with the sol! macro. The Router requires an import
  // https://github.com/alloy-rs/core/issues/602
  sol(
    &[
      "../../../networks/ethereum/schnorr/contracts/Schnorr.sol",
      "contracts/IRouter.sol",
      "contracts/Router.sol",
    ],
    &(artifacts_path.clone() + "/router.rs"),
  );

  let test_artifacts_path = artifacts_path + "/tests";
  if !fs::exists(&test_artifacts_path).unwrap() {
    fs::create_dir(&test_artifacts_path).unwrap();
  }

  // Build the test contracts
  build_solidity_contracts::build(
    &["../../../networks/ethereum/schnorr/contracts", "../erc20/contracts", "contracts"],
    "contracts/tests",
    &test_artifacts_path,
  )
  .unwrap();
}

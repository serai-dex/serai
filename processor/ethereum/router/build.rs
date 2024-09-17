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
    &["../../../networks/ethereum/schnorr/contracts", "../erc20/contracts"],
    "contracts",
    &artifacts_path,
  )
  .unwrap();

  // This cannot be handled with the sol! macro. The Solidity requires an import
  // https://github.com/alloy-rs/core/issues/602
  sol(
    &["../../../networks/ethereum/schnorr/contracts/Schnorr.sol", "contracts/Router.sol"],
    &(artifacts_path + "/router.rs"),
  );
}

use std::{env, fs};

fn main() {
  let artifacts_path = env::var("OUT_DIR").unwrap().to_string() + "/ethereum-schnorr-contract";
  if !fs::exists(&artifacts_path).unwrap() {
    fs::create_dir(&artifacts_path).unwrap();
  }
  build_solidity_contracts::build(&[], "contracts", &artifacts_path).unwrap();
}

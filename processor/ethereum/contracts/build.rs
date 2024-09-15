use std::{env, fs};

use alloy_sol_macro_input::{SolInputKind, SolInput};

fn write(sol: syn_solidity::File, file: &str) {
  let sol = alloy_sol_macro_expander::expand::expand(sol).unwrap();
  fs::write(
    file,
    // TODO: Replace `prettyplease::unparse` with `to_string`
    prettyplease::unparse(&syn::File {
      attrs: vec![],
      items: vec![syn::parse2(sol).unwrap()],
      shebang: None,
    })
    .as_bytes(),
  )
  .unwrap();
}

fn sol(sol: &str, file: &str) {
  let alloy_sol_macro_input::SolInputKind::Sol(sol) =
    syn::parse_str(&std::fs::read_to_string(sol).unwrap()).unwrap()
  else {
    panic!("parsed .sol file wasn't SolInputKind::Sol");
  };
  write(sol, file);
}

fn abi(ident: &str, abi: &str, file: &str) {
  let SolInputKind::Sol(sol) = (SolInput {
    attrs: vec![],
    path: None,
    kind: SolInputKind::Json(
      syn::parse_str(ident).unwrap(),
      serde_json::from_str(&fs::read_to_string(abi).unwrap()).unwrap(),
    ),
  })
  .normalize_json()
  .unwrap()
  .kind
  else {
    panic!("normalized JSON wasn't SolInputKind::Sol");
  };
  write(sol, file);
}

fn main() {
  let artifacts_path =
    env::var("OUT_DIR").unwrap().to_string() + "/serai-processor-ethereum-contracts";
  build_solidity_contracts::build(
    &["../../../networks/ethereum/schnorr/contracts"],
    "contracts",
    &artifacts_path,
  )
  .unwrap();

  // TODO: Use OUT_DIR for the generated code
  if !fs::exists("src/abigen").unwrap() {
    fs::create_dir("src/abigen").unwrap();
  }

  // These can be handled with the sol! macro
  sol("contracts/IERC20.sol", "src/abigen/erc20.rs");
  sol("contracts/Deployer.sol", "src/abigen/deployer.rs");
  // This cannot be handled with the sol! macro. The Solidity requires an import, the ABI is built
  // to OUT_DIR and the macro doesn't support non-static paths:
  // https://github.com/alloy-rs/core/issues/738
  abi("Router", &(artifacts_path.clone() + "/Router.abi"), "src/abigen/router.rs");
}

use alloy_sol_macro::sol;

#[rustfmt::skip]
#[allow(warnings)]
#[allow(needless_pass_by_value)]
#[allow(clippy::all)]
#[allow(clippy::ignored_unit_patterns)]
#[allow(clippy::redundant_closure_for_method_calls)]
mod erc20_container {
  use super::*;
  sol!("contracts/IERC20.sol");
}
pub use erc20_container::IERC20 as erc20;

#[rustfmt::skip]
#[allow(warnings)]
#[allow(needless_pass_by_value)]
#[allow(clippy::all)]
#[allow(clippy::ignored_unit_patterns)]
#[allow(clippy::redundant_closure_for_method_calls)]
mod deployer_container {
  use super::*;
  sol!("contracts/Deployer.sol");
}
pub use deployer_container::Deployer as deployer;

#[rustfmt::skip]
#[allow(warnings)]
#[allow(needless_pass_by_value)]
#[allow(clippy::all)]
#[allow(clippy::ignored_unit_patterns)]
#[allow(clippy::redundant_closure_for_method_calls)]
mod router_container {
  use super::*;
  sol!(Router, "artifacts/Router.abi");
}
pub use router_container::Router as router;

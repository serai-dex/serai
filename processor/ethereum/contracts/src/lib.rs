use alloy_sol_types::sol;

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod erc20_container {
  use super::*;
  sol!("contracts/IERC20.sol");
}
pub mod erc20 {
  pub const BYTECODE: &str = include_str!("../artifacts/Deployer.bin");
  pub use super::erc20_container::IERC20::*;
}

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod deployer_container {
  use super::*;
  sol!("contracts/Deployer.sol");
}
pub mod deployer {
  pub const BYTECODE: &str = include_str!("../artifacts/Deployer.bin");
  pub use super::deployer_container::Deployer::*;
}

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod router_container {
  use super::*;
  sol!(Router, "artifacts/Router.abi");
}
pub mod router {
  pub const BYTECODE: &str = include_str!("../artifacts/Router.bin");
  pub use super::router_container::Router::*;
}

pub mod tests;

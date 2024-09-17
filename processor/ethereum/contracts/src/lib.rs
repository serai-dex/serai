#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod abigen;

pub mod erc20 {
  pub use super::abigen::erc20::IERC20::*;
}
pub mod router {
  pub const BYTECODE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/serai-processor-ethereum-contracts/Router.bin"));
  pub use super::abigen::router::Router::*;
}

use alloy_sol_types::sol;

#[rustfmt::skip]
#[allow(warnings)]
#[allow(needless_pass_by_value)]
#[allow(clippy::all)]
#[allow(clippy::ignored_unit_patterns)]
#[allow(clippy::redundant_closure_for_method_calls)]
mod schnorr_container {
  use super::*;
  sol!("contracts/tests/Schnorr.sol");
}
pub use schnorr_container::TestSchnorr as schnorr;

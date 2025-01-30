use alloy_sol_types::SolCall;

#[test]
fn selector_collisions() {
  assert_eq!(
    crate::abi::IERC20::transferCall::SELECTOR,
    crate::abi::SeraiIERC20::transferWithInInstruction01BB244A8ACall::SELECTOR
  );
  assert_eq!(
    crate::abi::IERC20::transferFromCall::SELECTOR,
    crate::abi::SeraiIERC20::transferFromWithInInstruction00081948E0Call::SELECTOR
  );
}

// This is primarily tested via serai-processor-ethereum-router

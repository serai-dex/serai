use alloy_sol_types::SolCall as _;

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

#[test]
fn abi_decode_panic() {
  use alloy_sol_types::SolInterface as _;

  /*
    The following code panics with alloy-core 0.8, when the validate flag (commented out) is set to
    `false`. This flag was removed with alloy-core 1.0, leaving the default behavior of
    `abi_decode` to be `validate = false`. This test was added to ensure when we removed our
    practice of `validate = true`, we didn't open ourselves up this as a DoS risk.
  */
  assert!(
    crate::SeraiIERC20Calls::abi_decode(
      &alloy_core::primitives::hex::decode(concat!(
        "a9059cbb",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000006f",
        "ffffffffff000000000000000000000000000000000000000000000000000023",
        "000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffff0000000000000000000000000000000000000000000000000000000000",
      ))
      .unwrap(),
      // false
    )
    .is_err()
  );
}

// This is primarily tested via serai-processor-ethereum-router

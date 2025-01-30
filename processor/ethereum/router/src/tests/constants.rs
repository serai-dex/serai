use alloy_sol_types::SolCall;

#[test]
fn selector_collisions() {
  assert_eq!(
    crate::_irouter_abi::IRouter::confirmNextSeraiKeyCall::SELECTOR,
    crate::_router_abi::Router::confirmNextSeraiKey34AC53ACCall::SELECTOR
  );
  assert_eq!(
    crate::_irouter_abi::IRouter::updateSeraiKeyCall::SELECTOR,
    crate::_router_abi::Router::updateSeraiKey5A8542A2Call::SELECTOR
  );
  assert_eq!(
    crate::_irouter_abi::IRouter::executeCall::SELECTOR,
    crate::_router_abi::Router::execute4DE42904Call::SELECTOR
  );
  assert_eq!(
    crate::_irouter_abi::IRouter::escapeHatchCall::SELECTOR,
    crate::_router_abi::Router::escapeHatchDCDD91CCCall::SELECTOR
  );
}

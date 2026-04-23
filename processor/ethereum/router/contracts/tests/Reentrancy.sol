// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity =0.8.34;

import "Router.sol";

// This inherits from the Router for visibility over Reentered
contract Reentrancy {
  error Reentered();

  constructor() {
    (bool success, bytes memory res) =
      msg.sender.call(abi.encodeWithSelector(Router.execute4DE42904.selector, ""));
    require(!success);
    // We can't compare `bytes memory` so we hash them and compare the hashes
    require(keccak256(res) == keccak256(abi.encode(Reentered.selector)));
  }
}

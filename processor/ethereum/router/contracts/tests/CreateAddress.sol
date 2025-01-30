// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

import "Router.sol";

// Wrap the Router with a contract which exposes the createAddress function
contract CreateAddress is Router {
  constructor() Router(bytes32(uint256(1))) { }

  function createAddressForSelf(uint256 nonce) external returns (address) {
    return Router.createAddress(nonce);
  }
}

// SPDX-License-Identifier: AGPLv3

pragma solidity ^0.8.0;

struct Call {
  address to;
  uint256 value;
  bytes data;
}

// A minimal sandbox focused on gas efficiency.
//
// The first call is executed if any of the calls fail, making it a fallback.
// All other calls are executed sequentially.
contract Sandbox {
  error AlreadyCalled();
  error CallsFailed();

  receive() external payable {}

  function sandbox(Call[] calldata calls) external payable {
    // Prevent re-entrancy due to this executing arbitrary calls from anyone
    // and anywhere
    bool called;
    assembly { called := tload(0) }
    if (called) {
      revert AlreadyCalled();
    }
    assembly { tstore(0, 1) }

    // Execute the calls, starting from 1
    for (uint256 i = 1; i < calls.length; i++) {
      (bool success, ) =
        calls[i].to.call{ value: calls[i].value }(calls[i].data);

      // If this call failed, execute the fallback (call 0)
      if (!success) {
        (success, ) =
          calls[0].to.call{ value: address(this).balance }(calls[0].data);
        // If this call also failed, revert entirely
        if (!success) {
          revert CallsFailed();
        }
        return;
      }
    }

    // We don't clear the re-entrancy guard as this contract should never be
    // called again, so there's no reason to spend the effort
  }
}

//SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "./Schnorr.sol";

contract Router is Schnorr {
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
    }

    event Executed(bool success, bytes data);

    // execute accepts a list of transactions to execute as well as a Schnorr signature.
    // if signature verification passes, the given transactions are executed.
    // if signature verification fails, this function will revert.
    // if any of the executed transactions fail, this function will return false but *not* revert.
    // if all the executed transactions succeed, this function returns true.
    function execute(
        Transaction[] calldata transactions, 
        uint8 parity,
        bytes32 px,
        bytes32 s,
        bytes32 e
    ) public returns (bool) {
        bytes32 message = keccak256(abi.encode(transactions));
        require(verify(parity, px, message, s, e), "failed to verify signature");
        bool allOk = true;
        for(uint256 i = 0; i < transactions.length; i++) {
                (bool success, bytes memory returndata) = transactions[i].to.call{value: transactions[i].value}(
                    transactions[i].data
                );
                emit Executed(success, returndata);
                allOk = success && allOk;
        }
        return allOk;
    }
}
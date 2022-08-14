//SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "./Schnorr.sol";

contract Router is Schnorr {
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
    }

    constructor() {}

    event Executed(bool success, bytes data);

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

    function executeNoABIEncode(
        Transaction[] calldata transactions, 
        uint8 parity,
        bytes32 px,
        bytes32 s,
        bytes32 e
    ) public returns (bool) {
        bytes32 message;
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, sub(calldatasize(), 128))
            message := keccak256(ptr, sub(calldatasize(), 128))
        }
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
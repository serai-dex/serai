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

    function execute(
        Transaction[] calldata transactions, 
        uint8 parity,
        bytes32 px,
        bytes32 s,
        bytes32 e
    ) public {
        bytes32 message = keccak256(abi.encode(transactions));
        require(verify(parity, px, message, s, e));
        for(uint256 i = 0; i < transactions.length; i++) {
                (bool success, bytes memory returndata) = transactions[i].to.call{value: transactions[i].value}(
                    transactions[i].data
                );
                emit Executed(success, returndata);
        }
    }

    function executeNoABIEncode(
        Transaction[] calldata transactions, 
        uint8 parity,
        bytes32 px,
        bytes32 s,
        bytes32 e
    ) public {
        // uint256 signatureSize = 104; // idk don't actually store this
        bytes32 message;
        assembly {
            calldatacopy(0x40, 0, sub(calldatasize(), 104))
            message := keccak256(0x40, sub(calldatasize(), 104))
        }
        require(verify(parity, px, message, s, e));
        for(uint256 i = 0; i < transactions.length; i++) {
                (bool success, bytes memory returndata) = transactions[i].to.call{value: transactions[i].value}(
                    transactions[i].data
                );
                emit Executed(success, returndata);
        }
    }
}
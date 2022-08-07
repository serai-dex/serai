//SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

contract MockRecipient {
    function callMe() public payable {
        payable(msg.sender).transfer(msg.value);
    }
}
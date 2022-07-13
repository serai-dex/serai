//SPDX-License-Identifier: LGPLv3
pragma solidity ^0.8.0;

contract Schnorr {
    // sr := -s*P_x
    // er := -e*P_x
    // px := public key x-coord
    // parity := public key y-coord parity (27 or 28)
    // message := 32-byte message
    // e := schnorr signature challenge
    function verify(bytes32 sr, bytes32 er, bytes32 px, uint8 parity, bytes32 message, bytes32 e) public view returns (bool) {
        // ecrecover = (m, v, r, s);
        require(sr != 0);
        address q = ecrecover(sr, parity, px, er);
        return e == keccak256(abi.encodePacked(q, uint8(parity), px, block.chainid, message));
    }
}
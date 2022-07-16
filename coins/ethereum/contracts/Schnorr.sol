//SPDX-License-Identifier: LGPLv3
pragma solidity ^0.8.0;

// see https://github.com/noot/schnorr-verify for implementation details
contract Schnorr {
    // secp256k1 group order
    uint256 constant public Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // s := schnorr signature 
    // px := public key x-coord
    // parity := public key y-coord parity (27 or 28)
    // message := 32-byte message
    // e := schnorr signature challenge
    function verify(bytes32 s, bytes32 px, uint8 parity, bytes32 message, bytes32 e) public view returns (bool) {
        // ecrecover = (m, v, r, s);
        bytes32 sr = bytes32(Q - mulmod(uint256(s), uint256(px), Q));
        bytes32 er = bytes32(Q - mulmod(uint256(e), uint256(px), Q));

        require(sr != 0);
        // the ecrecover precompile implementation checks that the `r` and `s` inputs are non-zero
        // (in this case, `px` and `er`), thus we don't need to check if they're zero.
        address q = ecrecover(sr, parity, px, er);
        return e == keccak256(abi.encodePacked(q, uint8(parity), px, block.chainid, message));
    }
}
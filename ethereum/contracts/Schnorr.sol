//SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

import "./EC.sol";
import "hardhat/console.sol";

contract Schnorr is EC {
	function verify(uint256 s, uint256 e, uint256[2] memory pubkey, uint256 message) public view returns (bool) {
		(uint256 sGx, uint256 sGy, uint256 sGz) = EC._ecMul(s, gx, gy, 1);
		(uint256 eYx, uint256 eYy, uint256 eYz) = EC._ecMul(e, pubkey[0], pubkey[1], 1);

		(uint256 rx, uint256 ry, uint256 rz) = EC._ecAdd(sGx, sGy, sGz, eYx, eYy, eYz);

        rz = _inverse(rz);
        bytes32 qx = bytes32(mulmod(rx , rz ,n));
        // //bytes32 qy = bytes32(mulmod(ry , rz ,n));

        // for (uint i=0; i < 32; i++) {
        // 	console.log(uint8(qx[i]));
        // }

		return bytes32(e) == keccak256(abi.encode(qx,/* ry, pubkey[0], pubkey[1], */message));
	}
}
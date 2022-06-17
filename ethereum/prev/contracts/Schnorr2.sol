//SPDX-License-Identifier: LGPLv3
pragma solidity ^0.8.0;

import "hardhat/console.sol";

contract Schnorr2 {
    // uint256 constant gx =
    //     0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    // uint256 constant m =
    //     0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // sr := -s*P_x
    // er := -e*P_x
    // px := public key x-coord
    // parity := public key y-coord parity (27 or 28)
    // message := 32-byte message
    // e := schnorr signature challenge
    function verify(bytes32 sr, bytes32 er, bytes32 px, uint8 parity, bytes32 message, bytes32 e) public view returns (bool) {
        // ecrecover = (m, v, r, s);
        address q = ecrecover(sr, parity, px, er);
        console.log(q);
        return e == keccak256(abi.encodePacked(q, message));
    }
}

/*
    // xj = R
    secp256k1_gej_set_ge(&xj, &x);
    // rn = 1/r
    secp256k1_scalar_inverse_var(&rn, sigr);
    // u1 = m/r
    secp256k1_scalar_mul(&u1, &rn, message);
    // u1 = -m/r
    secp256k1_scalar_negate(&u1, &u1);
    // u2 = s/r
    secp256k1_scalar_mul(&u2, &rn, sigs);
    // qj = xj * u2 + u1 * G
    // qj = R*s/r - m*G/r
    // qj = (1/r)(R*s - m*G)
    secp256k1_ecmult(&qj, &xj, &u2, &u1);
    secp256k1_ge_set_gej_var(pubkey, &qj);
    return !secp256k1_gej_is_infinity(&qj);
*/
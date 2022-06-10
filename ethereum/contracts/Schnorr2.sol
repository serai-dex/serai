pragma solidity ^0.8.0;

contract Schnorr2 {
    uint256 constant gx =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant m =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // s := schnorr signature s
    // px := public key x-coord
    // parity := public key y-coord parity (0 or 1)
    // message := hashed message
    // q := schnorr signature R * (1 / px)
    function verify(bytes32 s, bytes32 px, uint8 parity, bytes32 message, uint256 q) public pure returns (bool) {
        address qRes = ecrecover(s, 27 + parity, px, message);
        return uint160(q) == uint160(qRes);
    }
}

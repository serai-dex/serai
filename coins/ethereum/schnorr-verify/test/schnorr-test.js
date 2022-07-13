const { expect } = require("chai");
const { ethers } = require("hardhat");

const BigInteger = require('bigi')
const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')

const arrayify = ethers.utils.arrayify;

function sign(m, x) {
  var publicKey = secp256k1.publicKeyCreate(x);

  // R = G * k
  var k = randomBytes(32);
  var R = secp256k1.publicKeyCreate(k);

  // e = h(address(R) || m)
  var e = challenge(R, m);

  // xe = x * e
  var xe = secp256k1.privateKeyTweakMul(x, e);

  // s = k + xe
  var s = secp256k1.privateKeyTweakAdd(k, xe);
  return {R, s, e};
}

function challenge(R, m) {
  // convert R to address
  // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
  var R_uncomp = secp256k1.publicKeyConvert(R, false);
  var R_addr = arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32);

  // e = keccak256(address(R) || m)
  var e = arrayify(ethers.utils.solidityKeccak256(
      ["address", "uint256"],
      [R_addr, m]));

  return e;
}

function preprocessSig(m, R, s, px) {
  // pre-process for contract
  var e = challenge(R, m);

  // px = x-coordinate of public key
  // s' = -s*px
  // e' = -e*px
  var sr = secp256k1.privateKeyTweakMul(s, px);
  sr = secp256k1.privateKeyNegate(sr);
  var er = secp256k1.privateKeyTweakMul(e, px);
  er = secp256k1.privateKeyNegate(er);
  return {sr, er};
}

describe("Schnorr", function () {
  it("Should verify a signature", async function () {
    const Schnorr = await ethers.getContractFactory("Schnorr");
    const schnorr = await Schnorr.deploy();
    await schnorr.deployed();

    // generate privKey
    let privKey
    do {
      privKey = randomBytes(32)
    } while (!secp256k1.privateKeyVerify(privKey))

    var publicKey = secp256k1.publicKeyCreate(privKey);
    var px = publicKey.slice(1, 33);

    // message 
    var m = randomBytes(32);

    var sig = sign(m, privKey);
    var pre = preprocessSig(m, sig.R, sig.s, px);

    let gas = await schnorr.estimateGas.verify(
      pre.sr,
      pre.er,
      publicKey.slice(1, 33),
      publicKey[0] - 2 + 27,
      arrayify(m),
      sig.e,
    )
    console.log("verify gas cost:", gas);

    expect(await schnorr.verify(
      pre.sr,
      pre.er,
      publicKey.slice(1, 33),
      publicKey[0] - 2 + 27,
      arrayify(m),
      sig.e,
    )).to.equal(true);
  });
});

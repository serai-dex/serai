const { expect } = require("chai");
const { ethers } = require("hardhat");

const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')

const arrayify = ethers.utils.arrayify;

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

    // M
    var M = randomBytes(32);

    // R = G * r
    var nonce = randomBytes(32);
    var R = secp256k1.publicKeyCreate(nonce);

    // e = H(r_x || M)
    console.log("R", R.slice(0, 32));

    var e = arraify(ethers.utils.solidityKeccak256(
        ["bytes32", "uint256"],
        [R.slice(1, 33), M]));

    // xe = x * e
    var xe = secp256k1.privateKeyTweakMul(privKey, e);
    var xeNeg = secp256k1.privateKeyNegate(xe)

    // s = r - xe
    var s = secp256k1.privateKeyTweakAdd(nonce, xe);

    var fullPk = secp256k1.publicKeyConvert(publicKey, false);

    var S = secp256k1.publicKeyCreate(s);
    console.log("S", S);

    var eY = secp256k1.publicKeyTweakMul(publicKey, e);
    console.log("eY", eY)

    var R_p = secp256k1.publicKeyCombine([S, eY]);
    console.log("R_p", R_p)
    console.log("R", R)

    expect(await schnorr.verify(
      s,
      e,
      [fullPk.slice(1, 33), fullPk.slice(33, 65)],
      arrayify(M),
    )).to.equal(true);
  });
});

const { expect } = require("chai");
const { ethers } = require("hardhat");

const BigInteger = require('bigi')
const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')

const arrayify = ethers.utils.arrayify;

// describe("Schnorr", function () {
//   it("Should verify a signature", async function () {
//     const Schnorr = await ethers.getContractFactory("Schnorr");
//     const schnorr = await Schnorr.deploy();
//     await schnorr.deployed();

//     // generate privKey
//     let privKey
//     do {
//       privKey = randomBytes(32)
//     } while (!secp256k1.privateKeyVerify(privKey))

//     var publicKey = secp256k1.publicKeyCreate(privKey);

//     // M
//     var M = randomBytes(32);

//     // R = G * r
//     var nonce = randomBytes(32);
//     var R = secp256k1.publicKeyCreate(nonce);

//     // e = H(r_x || M)
//     console.log("R", R.slice(0, 32));

//     var e = arrayify(ethers.utils.solidityKeccak256(
//         ["bytes32", "uint256"],
//         [R.slice(1, 33), M]));

//     // xe = x * e
//     var xe = secp256k1.privateKeyTweakMul(privKey, e);
//     var xeNeg = secp256k1.privateKeyNegate(xe)

//     // s = r - xe
//     var s = secp256k1.privateKeyTweakAdd(nonce, xe);

//     var fullPk = secp256k1.publicKeyConvert(publicKey, false);

//     var S = secp256k1.publicKeyCreate(s);
//     console.log("S", S);

//     var eY = secp256k1.publicKeyTweakMul(publicKey, e);
//     console.log("eY", eY)

//     var R_p = secp256k1.publicKeyCombine([S, eY]);
//     console.log("R_p", R_p)
//     console.log("R", R)

//     let gas = await schnorr.estimateGas.verify(
//       s,
//       e,
//       [fullPk.slice(1, 33), fullPk.slice(33, 65)],
//       arrayify(M),
//     )
//     console.log("verify gas cost:", gas);

//     expect(await schnorr.verify(
//       s,
//       e,
//       [fullPk.slice(1, 33), fullPk.slice(33, 65)],
//       arrayify(M),
//     )).to.equal(true);
//   });
// });

function sign(m, x) {
  var publicKey = secp256k1.publicKeyCreate(x);

  // R = G * k
  var k = randomBytes(32);
  var R = secp256k1.publicKeyCreate(k);
  //console.log("R", R)

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
  console.log("R_addr", R_addr)
  console.log("keccak256(R)", ethers.utils.keccak256(R_uncomp.slice(1, 65))) // last 20 bytes are address

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

// function recoverEthers(m, R, s) {
//   var sig = new Uint8Array(65);
//   sig.set(R.slice(1, 33), 0) 
//   sig.set(s, 32)
//   var parity = new Uint8Array(1);
//   parity[0] = R[0] - 2 + 27;
//   sig.set(parity, 64) // v

//   var q = ethers.utils.recoverPublicKey(m, sig)
//   console.log("recoverEthers q", arrayify(q))
//   return arrayify(q)
// }

// function getPublicKeyXCoord(priv) {
//   var publicKey = secp256k1.publicKeyCreate(priv);
//   return publicKey.slice(1, 33);
// }

describe("Schnorr2", function () {
  it("Should verify a signature", async function () {
    const Schnorr = await ethers.getContractFactory("Schnorr2");
    const schnorr = await Schnorr.deploy();
    await schnorr.deployed();

    // generate privKey
    let privKey
    do {
      privKey = randomBytes(32)
    } while (!secp256k1.privateKeyVerify(privKey))

    var publicKey = secp256k1.publicKeyCreate(privKey);
    //var publicKeyFull = secp256k1.publicKeyConvert(publicKey, false);
    var px = publicKey.slice(1, 33);

    // message 
    var m = randomBytes(32);

    var sig = sign(m, privKey);
    console.log(sig)
    // var px = getPublicKeyXCoord(privKey);

    var pre = preprocessSig(m, sig.R, sig.s, px);
    console.log(pre);

    // // manual recover
    // var eP = secp256k1.publicKeyTweakMul(publicKey, e);
    // eP = secp256k1.publicKeyNegate(eP);
    // var sG = secp256k1.publicKeyCreate(s);
    // var sum = secp256k1.publicKeyCombine([sG, eP]);
    // console.log(sum)

    // // manual recover 2
    // var eP = secp256k1.publicKeyTweakMul(publicKey, er);
    // //eP = secp256k1.publicKeyNegate(eP);
    // var sG = secp256k1.publicKeyCreate(sr);
    // sG = secp256k1.publicKeyNegate(sG);
    // var sum = secp256k1.publicKeyCombine([sG, eP]);
    // var Q = secp256k1.publicKeyTweakMul(sum, px_inv);
    // console.log(Q)

    //var fullPk = secp256k1.publicKeyConvert(publicKey, false);

    let gas = await schnorr.estimateGas.verify(
    pre.sr,
      pre.er,
      publicKey.slice(1, 33),
      publicKey[0] - 2 + 27,
      arrayify(m),
      sig.e,
    )
    console.log("verify gas cost:", gas);

    // console.log("parity", publicKey[0] - 2);

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

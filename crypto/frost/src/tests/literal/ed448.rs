use rand_core::OsRng;

use ciphersuite::Ciphersuite;

use schnorr::SchnorrSignature;

use crate::{
  curve::{Ed448, Ietf8032Ed448Hram, IetfEd448Hram},
  tests::vectors::{Vectors, test_with_vectors},
};

// This is a vector from RFC 8032 to sanity check the HRAM is properly implemented
// The RFC 8032 Ed448 HRAM is much more complex than the other HRAMs, hence why it's helpful to
// have additional testing for it
// Additionally, FROST, despite being supposed to use the RFC 8032 HRAMs, originally applied
// Ed25519's HRAM to both Ed25519 and Ed448
// This test was useful when proposing the corrections to the spec to demonstrate the correctness
// the new algorithm/vectors
// While we could test all Ed448 vectors here, this is sufficient for sanity
#[test]
fn ed448_8032_vector() {
  let context = hex::decode("666f6f").unwrap();

  #[allow(non_snake_case)]
  let A = Ed448::read_G::<&[u8]>(
    &mut hex::decode(
      "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c".to_owned() +
        "6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a94" +
        "80",
    )
    .unwrap()
    .as_ref(),
  )
  .unwrap();

  let msg = hex::decode("03").unwrap();

  let sig = hex::decode(
    "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b3".to_owned() +
      "2a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea" +
      "00" +
      "0c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccb" +
      "bb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c" +
      "00",
  )
  .unwrap();
  #[allow(non_snake_case)]
  let R = Ed448::read_G::<&[u8]>(&mut sig.as_ref()).unwrap();
  let s = Ed448::read_F::<&[u8]>(&mut &sig[57 ..]).unwrap();

  assert!(
    SchnorrSignature::<Ed448> { R, s }.verify(A, Ietf8032Ed448Hram::hram(&context, &R, &A, &msg))
  );
}

#[test]
fn ed448_vectors() {
  test_with_vectors::<_, Ed448, IetfEd448Hram>(
    &mut OsRng,
    &Vectors::from(
      serde_json::from_str::<serde_json::Value>(include_str!("vectors/frost-ed448-shake256.json"))
        .unwrap(),
    ),
  );
}

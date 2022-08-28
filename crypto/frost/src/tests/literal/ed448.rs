use std::io::Cursor;

use rand_core::OsRng;

use crate::{
  curve::{Curve, Ed448, Ietf8032Ed448Hram, NonIetfEd448Hram},
  schnorr::{SchnorrSignature, verify},
  tests::vectors::{Vectors, test_with_vectors},
};

#[test]
fn ed448_8032_vector() {
  let context = hex::decode("666f6f").unwrap();

  #[allow(non_snake_case)]
  let A = Ed448::read_G(&mut Cursor::new(
    hex::decode(
      "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c".to_owned() +
        "6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a94" +
        "80",
    )
    .unwrap(),
  ))
  .unwrap();

  let msg = hex::decode("03").unwrap();

  let mut sig = Cursor::new(
    hex::decode(
      "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b3".to_owned() +
        "2a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea" +
        "00" +
        "0c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccb" +
        "bb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c" +
        "00",
    )
    .unwrap(),
  );
  #[allow(non_snake_case)]
  let R = Ed448::read_G(&mut sig).unwrap();
  let s = Ed448::read_F(&mut sig).unwrap();

  assert!(verify(
    A,
    Ietf8032Ed448Hram::hram(&context, &R, &A, &msg),
    &SchnorrSignature::<Ed448> { R, s }
  ));
}


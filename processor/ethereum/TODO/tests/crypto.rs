// TODO

use rand_core::OsRng;

use group::ff::{Field, PrimeField};
use k256::{
  ecdsa::{
    self, hazmat::SignPrimitive, signature::hazmat::PrehashVerifier, SigningKey, VerifyingKey,
  },
  Scalar, ProjectivePoint,
};

use frost::{
  curve::{Ciphersuite, Secp256k1},
  algorithm::{Hram, IetfSchnorr},
  tests::{algorithm_machines, sign},
};

use crate::{crypto::*, tests::key_gen};

// Run the sign test with the EthereumHram
#[test]
fn test_signing() {
  let (keys, _) = key_gen();

  const MESSAGE: &[u8] = b"Hello, World!";

  let algo = IetfSchnorr::<Secp256k1, EthereumHram>::ietf();
  let _sig =
    sign(&mut OsRng, &algo, keys.clone(), algorithm_machines(&mut OsRng, &algo, &keys), MESSAGE);
}

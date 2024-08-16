use std::time::Instant;

use rand_core::OsRng;

use zeroize::{Zeroize, Zeroizing};
use generic_array::typenum::{Sum, Diff, Quot, U, U1, U2};
use blake2::{Digest, Blake2b512};

use ciphersuite::{
  group::{
    ff::{FromUniformBytes, Field, PrimeField},
    Group,
  },
  Ciphersuite, Secp256k1, Ed25519, Ristretto,
};
use pasta_curves::{Ep, Eq, Fp, Fq};

use generalized_bulletproofs::tests::generators;
use generalized_bulletproofs_ec_gadgets::DiscreteLogParameters;

use crate::evrf::proof::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct Pallas;
impl Ciphersuite for Pallas {
  type F = Fq;
  type G = Ep;
  type H = Blake2b512;
  const ID: &'static [u8] = b"Pallas";
  fn generator() -> Ep {
    Ep::generator()
  }
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
    // This naive concat may be insecure in a real world deployment
    // This is solely test code so it's fine
    Self::F::from_uniform_bytes(&Self::H::digest([dst, msg].concat()).into())
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct Vesta;
impl Ciphersuite for Vesta {
  type F = Fp;
  type G = Eq;
  type H = Blake2b512;
  const ID: &'static [u8] = b"Vesta";
  fn generator() -> Eq {
    Eq::generator()
  }
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
    // This naive concat may be insecure in a real world deployment
    // This is solely test code so it's fine
    Self::F::from_uniform_bytes(&Self::H::digest([dst, msg].concat()).into())
  }
}

pub struct VestaParams;
impl DiscreteLogParameters for VestaParams {
  type ScalarBits = U<{ <<Vesta as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
  type XCoefficients = Quot<Sum<Self::ScalarBits, U1>, U2>;
  type XCoefficientsMinusOne = Diff<Self::XCoefficients, U1>;
  type YxCoefficients = Diff<Quot<Sum<Sum<Self::ScalarBits, U1>, U1>, U2>, U2>;
}

impl EvrfCurve for Pallas {
  type EmbeddedCurve = Vesta;
  type EmbeddedCurveParameters = VestaParams;
}

fn evrf_proof_test<C: EvrfCurve>() {
  let generators = generators(1024);
  let vesta_private_key = Zeroizing::new(<C::EmbeddedCurve as Ciphersuite>::F::random(&mut OsRng));
  let ecdh_public_keys = [
    <C::EmbeddedCurve as Ciphersuite>::G::random(&mut OsRng),
    <C::EmbeddedCurve as Ciphersuite>::G::random(&mut OsRng),
  ];
  let time = Instant::now();
  let res =
    Evrf::<C>::prove(&mut OsRng, &generators, [0; 32], 1, &ecdh_public_keys, &vesta_private_key)
      .unwrap();
  println!("Proving time: {:?}", time.elapsed());

  let time = Instant::now();
  let mut verifier = generators.batch_verifier();
  Evrf::<C>::verify(
    &mut OsRng,
    &generators,
    &mut verifier,
    [0; 32],
    1,
    &ecdh_public_keys,
    C::EmbeddedCurve::generator() * *vesta_private_key,
    &res.proof,
  )
  .unwrap();
  assert!(generators.verify(verifier));
  println!("Verifying time: {:?}", time.elapsed());
}

#[test]
fn pallas_evrf_proof_test() {
  evrf_proof_test::<Pallas>();
}

#[test]
fn secp256k1_evrf_proof_test() {
  evrf_proof_test::<Secp256k1>();
}

#[test]
fn ed25519_evrf_proof_test() {
  evrf_proof_test::<Ed25519>();
}

#[test]
fn ristretto_evrf_proof_test() {
  evrf_proof_test::<Ristretto>();
}

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
  Ciphersuite,
};
use pasta_curves::{Ep, Eq, Fp, Fq};

use generalized_bulletproofs::tests::generators;
use generalized_bulletproofs_ec_gadgets::DiscreteLogParameters;

use crate::evrf::proof::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
struct Pallas;
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
struct Vesta;
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

struct VestaParams;
impl DiscreteLogParameters for VestaParams {
  type ScalarBits = U<{ <<Vesta as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
  type XCoefficients = Quot<Sum<Self::ScalarBits, U1>, U2>;
  type XCoefficientsMinusOne = Diff<Self::XCoefficients, U1>;
  type YxCoefficients = Diff<Quot<Sum<Self::ScalarBits, U1>, U2>, U2>;
}

impl EvrfCurve for Pallas {
  type EmbeddedCurve = Vesta;
  type EmbeddedCurveParameters = VestaParams;
}

#[test]
fn evrf_proof_pasta_test() {
  let generators = generators(1024);
  let vesta_private_key = Zeroizing::new(<Vesta as Ciphersuite>::F::random(&mut OsRng));
  let ecdh_public_keys =
    [<Vesta as Ciphersuite>::G::random(&mut OsRng), <Vesta as Ciphersuite>::G::random(&mut OsRng)];
  let time = Instant::now();
  let res = Evrf::<Pallas>::prove(
    &mut OsRng,
    &generators,
    vesta_private_key.clone(),
    [0; 32],
    1,
    &ecdh_public_keys,
  )
  .unwrap();
  println!("Proving time: {:?}", time.elapsed());

  let time = Instant::now();
  let mut verifier = generators.batch_verifier();
  dbg!(Evrf::<Pallas>::verify(
    &mut OsRng,
    &generators,
    &mut verifier,
    Vesta::generator() * *vesta_private_key,
    [0; 32],
    1,
    &ecdh_public_keys,
    &res.proof,
  )
  .unwrap());
  assert!(generators.verify(verifier));
  println!("Verifying time: {:?}", time.elapsed());
}

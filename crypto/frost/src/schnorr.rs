use rand_core::{RngCore, CryptoRng};

use group::{ff::{Field, PrimeField}, GroupEncoding};

use multiexp::BatchVerifier;

use crate::Curve;

#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SchnorrSignature<C: Curve> {
  pub R: C::G,
  pub s: C::F,
}

impl<C: Curve> SchnorrSignature<C> {
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(C::G_len() + C::F_len());
    res.extend(self.R.to_bytes().as_ref());
    res.extend(self.s.to_repr().as_ref());
    res
  }
}

pub(crate) fn sign<C: Curve>(
  private_key: C::F,
  nonce: C::F,
  challenge: C::F
) -> SchnorrSignature<C> {
  SchnorrSignature {
    R: C::GENERATOR * nonce,
    s: nonce + (private_key * challenge)
  }
}

#[must_use]
pub(crate) fn verify<C: Curve>(
  public_key: C::G,
  challenge: C::F,
  signature: &SchnorrSignature<C>
) -> bool {
  (C::GENERATOR * signature.s) == (signature.R + (public_key * challenge))
}

pub(crate) fn batch_verify<C: Curve, R: RngCore + CryptoRng>(
  rng: &mut R,
  triplets: &[(u16, C::G, C::F, SchnorrSignature<C>)]
) -> Result<(), u16> {
  let mut values = [(C::F::one(), C::GENERATOR); 3];
  let mut batch = BatchVerifier::new(triplets.len());
  for triple in triplets {
    // s = r + ca
    // sG == R + cA
    // R + cA - sG == 0

    // R
    values[0].1 = triple.3.R;
    // cA
    values[1] = (triple.2, triple.1);
    // -sG
    values[2].0 = -triple.3.s;

    batch.queue(rng, triple.0, values);
  }

  batch.verify_vartime_with_vartime_blame()
}

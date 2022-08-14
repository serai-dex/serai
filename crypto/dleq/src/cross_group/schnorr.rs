use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use transcript::Transcript;

use curve::{ff::Field, group::GroupEncoding, Curve, CurveError};
use multiexp::BatchVerifier;

use crate::challenge;

#[cfg(feature = "serialize")]
use std::io::{Read, Write};
#[cfg(feature = "serialize")]
use curve::ff::PrimeField;

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct SchnorrPoK<C: Curve> {
  R: C::G,
  s: C::F,
}

impl<C: Curve> SchnorrPoK<C> {
  // Not hram due to the lack of m
  #[allow(non_snake_case)]
  fn hra<T: Transcript>(transcript: &mut T, generator: C::G, R: C::G, A: C::G) -> C::F {
    transcript.domain_separate(b"schnorr_proof_of_knowledge");
    transcript.append_message(b"generator", generator.to_bytes().as_ref());
    transcript.append_message(b"nonce", R.to_bytes().as_ref());
    transcript.append_message(b"public_key", A.to_bytes().as_ref());
    challenge::<_, C>(transcript)
  }

  pub(crate) fn prove<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generator: C::G,
    mut private_key: C::F,
  ) -> SchnorrPoK<C> {
    let mut nonce = C::F::random(rng);
    #[allow(non_snake_case)]
    let R = generator * nonce;
    let res = SchnorrPoK {
      R,
      s: nonce +
        (private_key * SchnorrPoK::<C>::hra(transcript, generator, R, generator * private_key)),
    };
    private_key.zeroize();
    nonce.zeroize();
    res
  }

  pub(crate) fn verify<R: RngCore + CryptoRng, T: Transcript>(
    &self,
    rng: &mut R,
    transcript: &mut T,
    generator: C::G,
    public_key: C::G,
    batch: &mut BatchVerifier<(), C::G>,
  ) {
    batch.queue(
      rng,
      (),
      [
        (-self.s, generator),
        (C::F::one(), self.R),
        (Self::hra(transcript, generator, self.R, public_key), public_key),
      ],
    );
  }

  #[cfg(feature = "serialize")]
  pub fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.R.to_bytes().as_ref())?;
    w.write_all(self.s.to_repr().as_ref())
  }

  #[cfg(feature = "serialize")]
  pub fn deserialize<R: Read>(r: &mut R) -> Result<SchnorrPoK<C>, CurveError> {
    Ok(SchnorrPoK { R: C::read_G(r)?, s: C::read_F(r)? })
  }
}

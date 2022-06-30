use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;

use group::{ff::Field, prime::PrimeGroup};

use crate::challenge;

#[cfg(feature = "serialize")]
use std::io::{Read, Write};
#[cfg(feature = "serialize")]
use ff::PrimeField;
#[cfg(feature = "serialize")]
use crate::{read_scalar, cross_group::read_point};

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct SchnorrPoK<G: PrimeGroup> {
  R: G,
  s: G::Scalar
}

impl<G: PrimeGroup> SchnorrPoK<G> {
  // Not hram due to the lack of m
  #[allow(non_snake_case)]
  fn hra<T: Transcript>(transcript: &mut T, generator: G, R: G, A: G) -> G::Scalar {
    transcript.domain_separate(b"schnorr_proof_of_knowledge");
    transcript.append_message(b"generator", generator.to_bytes().as_ref());
    transcript.append_message(b"nonce", R.to_bytes().as_ref());
    transcript.append_message(b"public_key", A.to_bytes().as_ref());
    challenge(transcript, b"challenge")
  }

  pub(crate) fn prove<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generator: G,
    private_key: G::Scalar
  ) -> SchnorrPoK<G> {
    let nonce = G::Scalar::random(rng);
    #[allow(non_snake_case)]
    let R = generator * nonce;
    SchnorrPoK {
      R,
      s: nonce + (private_key * SchnorrPoK::hra(transcript, generator, R, generator * private_key))
    }
  }

  #[must_use]
  pub(crate) fn verify<T: Transcript>(
    &self,
    transcript: &mut T,
    generator: G,
    public_key: G
  ) -> bool {
    (generator * self.s) == (
      self.R + (public_key * Self::hra(transcript, generator, self.R, public_key))
    )
  }

  #[cfg(feature = "serialize")]
  pub fn serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.R.to_bytes().as_ref())?;
    w.write_all(self.s.to_repr().as_ref())
  }

  #[cfg(feature = "serialize")]
  pub fn deserialize<R: Read>(r: &mut R) -> std::io::Result<SchnorrPoK<G>> {
    Ok(SchnorrPoK { R: read_point(r)?, s: read_scalar(r)? })
  }
}

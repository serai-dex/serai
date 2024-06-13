use core::ops::Deref;

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use transcript::Transcript;

use group::{
  ff::{Field, PrimeFieldBits},
  prime::PrimeGroup,
};
use multiexp::BatchVerifier;

use crate::challenge;

#[cfg(feature = "serialize")]
use std::io::{Read, Write};
#[cfg(feature = "serialize")]
use ff::PrimeField;
#[cfg(feature = "serialize")]
use crate::{read_scalar, cross_group::read_point};

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct SchnorrPoK<G: PrimeGroup + Zeroize> {
  R: G,
  s: G::Scalar,
}

impl<G: PrimeGroup<Scalar: PrimeFieldBits + Zeroize> + Zeroize> SchnorrPoK<G> {
  // Not HRAm due to the lack of m
  #[allow(non_snake_case)]
  fn hra<T: Transcript>(transcript: &mut T, generator: G, R: G, A: G) -> G::Scalar {
    transcript.domain_separate(b"schnorr_proof_of_knowledge");
    transcript.append_message(b"generator", generator.to_bytes());
    transcript.append_message(b"nonce", R.to_bytes());
    transcript.append_message(b"public_key", A.to_bytes());
    challenge(transcript)
  }

  pub(crate) fn prove<R: RngCore + CryptoRng, T: Transcript>(
    rng: &mut R,
    transcript: &mut T,
    generator: G,
    private_key: &Zeroizing<G::Scalar>,
  ) -> SchnorrPoK<G> {
    let nonce = Zeroizing::new(G::Scalar::random(rng));
    #[allow(non_snake_case)]
    let R = generator * nonce.deref();
    SchnorrPoK {
      R,
      s: (SchnorrPoK::hra(transcript, generator, R, generator * private_key.deref()) *
        private_key.deref()) +
        nonce.deref(),
    }
  }

  pub(crate) fn verify<R: RngCore + CryptoRng, T: Transcript>(
    &self,
    rng: &mut R,
    transcript: &mut T,
    generator: G,
    public_key: G,
    batch: &mut BatchVerifier<(), G>,
  ) {
    batch.queue(
      rng,
      (),
      [
        (-self.s, generator),
        (G::Scalar::ONE, self.R),
        (Self::hra(transcript, generator, self.R, public_key), public_key),
      ],
    );
  }

  #[cfg(feature = "serialize")]
  pub fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
    w.write_all(self.R.to_bytes().as_ref())?;
    w.write_all(self.s.to_repr().as_ref())
  }

  #[cfg(feature = "serialize")]
  pub fn read<R: Read>(r: &mut R) -> std::io::Result<SchnorrPoK<G>> {
    Ok(SchnorrPoK { R: read_point(r)?, s: read_scalar(r)? })
  }
}

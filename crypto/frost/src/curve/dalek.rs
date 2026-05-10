use subtle::CtOption;
use zeroize::Zeroize;
use ciphersuite::{
  digest::Digest as _, group::GroupEncoding, FromUniformBytes as _, WrappedGroup, WithPreferredHash,
};
use dalek_ff_group::Scalar;

use crate::{curve::Curve, algorithm::Hram};

macro_rules! dalek_curve {
  (
    $Curve:      ident,
    $Hram:       ident,

    $CONTEXT: literal,
    $chal: literal
  ) => {
    impl Curve for $Curve {
      const CONTEXT: &'static [u8] = $CONTEXT;
      fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
        let mut digest = <Self as WithPreferredHash>::H::new();
        digest.update(Self::CONTEXT);
        digest.update(dst);
        digest.update(msg);
        Self::F::from_uniform_bytes(&digest.finalize().into())
      }
    }

    /// The challenge function for this ciphersuite.
    #[derive(Copy, Clone)]
    pub struct $Hram;
    impl Hram<$Curve> for $Hram {
      #[expect(non_snake_case)]
      fn hram(
        R: &<$Curve as WrappedGroup>::G,
        A: &<$Curve as WrappedGroup>::G,
        m: &[u8],
      ) -> Scalar {
        let mut hash = <$Curve as WithPreferredHash>::H::new();
        if $chal.len() != 0 {
          hash.update($CONTEXT);
          hash.update($chal);
        }
        hash.update(R.compress().to_bytes());
        hash.update(A.compress().to_bytes());
        hash.update(m);
        Scalar::from_uniform_bytes(&hash.finalize().into())
      }
    }
  };
}

/*
  FROST defined Ristretto as using SHA2-512, while Blake2b512 is considered "preferred" by
  `dalek-ff-group`. We define our own ciphersuite for it accordingly.
*/
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Ristretto;
impl WrappedGroup for Ristretto {
  type F = Scalar;
  type G = dalek_ff_group::RistrettoPoint;
  fn generator() -> Self::G {
    dalek_ff_group::Ristretto::generator()
  }
}
impl ciphersuite::Id for Ristretto {
  const ID: &[u8] = b"FROST-RISTRETTO255";
}
impl WithPreferredHash for Ristretto {
  type H = <Ed25519 as WithPreferredHash>::H;
}
impl ciphersuite::GroupCanonicalEncoding for Ristretto {
  fn from_canonical_bytes(bytes: &<Self::G as GroupEncoding>::Repr) -> CtOption<Self::G> {
    dalek_ff_group::Ristretto::from_canonical_bytes(bytes)
  }
}
dalek_curve!(Ristretto, IrtfRistrettoHram, b"FROST-RISTRETTO255-SHA512-v1", b"chal");

pub use dalek_ff_group::Ed25519;
dalek_curve!(Ed25519, IrtfEd25519Hram, b"FROST-ED25519-SHA512-v1", b"");

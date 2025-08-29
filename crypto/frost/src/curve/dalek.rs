use ciphersuite::{digest::Digest, FromUniformBytes, Ciphersuite};
use dalek_ff_group::Scalar;

use crate::{curve::Curve, algorithm::Hram};

macro_rules! dalek_curve {
  (
    $feature: literal,

    $Curve:      ident,
    $Hram:       ident,

    $CONTEXT: literal,
    $chal: literal
  ) => {
    pub use dalek_ff_group::$Curve;

    impl Curve for $Curve {
      const CONTEXT: &'static [u8] = $CONTEXT;
      fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
        let mut digest = <Self as Ciphersuite>::H::new();
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
      #[allow(non_snake_case)]
      fn hram(R: &<$Curve as Ciphersuite>::G, A: &<$Curve as Ciphersuite>::G, m: &[u8]) -> Scalar {
        let mut hash = <$Curve as Ciphersuite>::H::new();
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

#[cfg(feature = "ristretto")]
dalek_curve!("ristretto", Ristretto, IetfRistrettoHram, b"FROST-RISTRETTO255-SHA512-v1", b"chal");

#[cfg(feature = "ed25519")]
dalek_curve!("ed25519", Ed25519, IetfEd25519Hram, b"FROST-ED25519-SHA512-v1", b"");

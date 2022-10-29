use digest::Digest;

use dalek_ff_group::Scalar;

use ciphersuite::Ciphersuite;

use crate::{curve::Curve, algorithm::Hram};

macro_rules! dalek_curve {
  (
    $feature: literal,

    $Curve:      ident,
    $Hram:       ident,

    $CONTEXT: literal,
    $chal: literal
  ) => {
    pub use ciphersuite::$Curve;

    impl Curve for $Curve {
      const CONTEXT: &'static [u8] = $CONTEXT;
    }

    #[derive(Copy, Clone)]
    pub struct $Hram;
    impl Hram<$Curve> for $Hram {
      #[allow(non_snake_case)]
      fn hram(R: &<$Curve as Ciphersuite>::G, A: &<$Curve as Ciphersuite>::G, m: &[u8]) -> Scalar {
        let mut hash = <$Curve as Ciphersuite>::H::new();
        if $chal.len() != 0 {
          hash.update(&[$CONTEXT.as_ref(), $chal].concat());
        }
        Scalar::from_hash(
          hash.chain_update(&[&R.compress().to_bytes(), &A.compress().to_bytes(), m].concat()),
        )
      }
    }
  };
}

#[cfg(feature = "ristretto")]
dalek_curve!("ristretto", Ristretto, IetfRistrettoHram, b"FROST-RISTRETTO255-SHA512-v11", b"chal");

#[cfg(feature = "ed25519")]
dalek_curve!("ed25519", Ed25519, IetfEd25519Hram, b"FROST-ED25519-SHA512-v11", b"");

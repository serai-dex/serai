use group::GroupEncoding;

use ciphersuite::Ciphersuite;

use crate::{curve::Curve, algorithm::Hram};

macro_rules! kp_curve {
  (
    $feature: literal,

    $Curve: ident,
    $Hram:  ident,

    $CONTEXT: literal
  ) => {
    pub use ciphersuite::$Curve;

    impl Curve for $Curve {
      const CONTEXT: &'static [u8] = $CONTEXT;
    }

    #[derive(Clone)]
    pub struct $Hram;
    impl Hram<$Curve> for $Hram {
      #[allow(non_snake_case)]
      fn hram(
        R: &<$Curve as Ciphersuite>::G,
        A: &<$Curve as Ciphersuite>::G,
        m: &[u8],
      ) -> <$Curve as Ciphersuite>::F {
        <$Curve as Curve>::hash_to_F(
          b"chal",
          &[R.to_bytes().as_ref(), A.to_bytes().as_ref(), m].concat(),
        )
      }
    }
  };
}

#[cfg(feature = "p256")]
kp_curve!("p256", P256, IetfP256Hram, b"FROST-P256-SHA256-v11");

#[cfg(feature = "secp256k1")]
kp_curve!("secp256k1", Secp256k1, IetfSecp256k1Hram, b"FROST-secp256k1-SHA256-v11");

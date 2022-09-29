use zeroize::Zeroize;

use sha2::{Digest, Sha256};

use group::{
  ff::{Field, PrimeField},
  GroupEncoding,
};

use elliptic_curve::{
  generic_array::GenericArray,
  bigint::{Encoding, U384},
  hash2curve::{Expander, ExpandMsg, ExpandMsgXmd},
};

use crate::{curve::Curve, algorithm::Hram};

macro_rules! kp_curve {
  (
    $feature: literal,

    $lib:   ident,
    $Curve: ident,
    $Hram:  ident,

    $ID:      literal,
    $CONTEXT: literal
  ) => {
    #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
    pub struct $Curve;
    impl $Curve {
      fn hash(dst: &[u8], data: &[u8]) -> Sha256 {
        Sha256::new().chain_update(&[$CONTEXT.as_ref(), dst, data].concat())
      }
    }

    impl Curve for $Curve {
      type F = $lib::Scalar;
      type G = $lib::ProjectivePoint;

      const ID: &'static [u8] = $ID;

      fn generator() -> Self::G {
        $lib::ProjectivePoint::GENERATOR
      }

      fn hash_to_vec(dst: &[u8], data: &[u8]) -> Vec<u8> {
        Self::hash(dst, data).finalize().to_vec()
      }

      fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
        let mut dst = &[$CONTEXT, dst].concat();
        let oversize = Sha256::digest([b"H2C-OVERSIZE-DST-".as_ref(), dst].concat()).to_vec();
        if dst.len() > 255 {
          dst = &oversize;
        }

        // While one of these two libraries does support directly hashing to the Scalar field, the
        // other doesn't. While that's probably an oversight, this is a universally working method
        let mut modulus = vec![0; 16];
        modulus.extend((Self::F::zero() - Self::F::one()).to_bytes());
        let modulus = U384::from_be_slice(&modulus).wrapping_add(&U384::ONE);

        let mut unreduced = U384::from_be_bytes({
          let mut bytes = [0; 48];
          ExpandMsgXmd::<Sha256>::expand_message(&[msg], dst, 48).unwrap().fill_bytes(&mut bytes);
          bytes
        })
        .reduce(&modulus)
        .unwrap()
        .to_be_bytes();

        let mut array = *GenericArray::from_slice(&unreduced[16 ..]);
        let res = $lib::Scalar::from_repr(array).unwrap();
        unreduced.zeroize();
        array.zeroize();
        res
      }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
    #[derive(Clone)]
    pub struct $Hram;
    impl Hram<$Curve> for $Hram {
      #[allow(non_snake_case)]
      fn hram(R: &$lib::ProjectivePoint, A: &$lib::ProjectivePoint, m: &[u8]) -> $lib::Scalar {
        $Curve::hash_to_F(b"chal", &[R.to_bytes().as_ref(), A.to_bytes().as_ref(), m].concat())
      }
    }
  };
}

#[cfg(feature = "p256")]
kp_curve!("p256", p256, P256, IetfP256Hram, b"P-256", b"FROST-P256-SHA256-v10");

#[cfg(feature = "secp256k1")]
kp_curve!(
  "secp256k1",
  k256,
  Secp256k1,
  IetfSecp256k1Hram,
  b"secp256k1",
  b"FROST-secp256k1-SHA256-v10"
);

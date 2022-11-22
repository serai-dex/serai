use zeroize::Zeroize;

use sha2::{Digest, Sha256};

use group::ff::{Field, PrimeField};

use elliptic_curve::{
  generic_array::GenericArray,
  bigint::{Encoding, U384},
  hash2curve::{Expander, ExpandMsg, ExpandMsgXmd},
};

use crate::Ciphersuite;

macro_rules! kp_curve {
  (
    $feature: literal,
    $lib:     ident,

    $Ciphersuite: ident,
    $ID:          literal
  ) => {
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
    pub struct $Ciphersuite;
    impl Ciphersuite for $Ciphersuite {
      type F = $lib::Scalar;
      type G = $lib::ProjectivePoint;
      type H = Sha256;

      const ID: &'static [u8] = $ID;

      fn generator() -> Self::G {
        $lib::ProjectivePoint::GENERATOR
      }

      fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
        let mut dst = dst;
        let oversize = Sha256::digest([b"H2C-OVERSIZE-DST-".as_ref(), dst].concat());
        if dst.len() > 255 {
          dst = oversize.as_ref();
        }

        // While one of these two libraries does support directly hashing to the Scalar field, the
        // other doesn't. While that's probably an oversight, this is a universally working method
        let mut modulus = [0; 48];
        modulus[16 ..].copy_from_slice(&(Self::F::zero() - Self::F::one()).to_bytes());
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
  };
}

#[cfg(feature = "p256")]
kp_curve!("p256", p256, P256, b"P-256");

#[cfg(feature = "secp256k1")]
kp_curve!("secp256k1", k256, Secp256k1, b"secp256k1");

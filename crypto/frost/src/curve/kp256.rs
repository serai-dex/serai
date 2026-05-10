use core::convert::AsRef;

use sha2::{digest::Digest as _, Sha256};

use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField},
    GroupEncoding as _,
  },
  WrappedGroup,
};

use elliptic_curve::{
  zeroize::Zeroize as _,
  generic_array::{typenum::U32, GenericArray},
  bigint::{NonZero, CheckedAdd as _, Encoding as _, U384},
  hash2curve::{Expander as _, ExpandMsg as _, ExpandMsgXmd},
};

use crate::{curve::Curve, algorithm::Hram};

#[expect(non_snake_case)]
fn hash_to_F<C: WrappedGroup<F: PrimeField<Repr = GenericArray<u8, U32>>>>(
  dst: &[u8],
  msg: &[u8],
) -> C::F {
  // While one of these two libraries does support directly hashing to the Scalar field, the
  // other doesn't. While that's probably an oversight, this is a universally working method

  // This method is from
  // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html
  // Specifically, Section 5

  // While that draft, overall, is intended for hashing to curves, that necessitates
  // detailing how to hash to a finite field. The draft comments that its mechanism for
  // doing so, which it uses to derive field elements, is also applicable to the scalar field

  // The hash_to_field function is intended to provide unbiased values
  // In order to do so, a wide reduction from an extra k bits is applied, minimizing bias to
  // 2^-k
  // k is intended to be the bits of security of the suite, which is 128 for secp256k1 and
  // P-256
  const K: usize = 128;

  // L is the amount of bytes of material which should be used in the wide reduction
  // The 256 is for the bit-length of the primes, rounded up to the nearest byte threshold
  // This is a simplification of the formula from the end of section 5
  const L: usize = (256 + K) / 8; // 48

  // In order to perform this reduction, we need to use 48-byte numbers
  // First, convert the modulus to a 48-byte number
  // This is done by getting -1 as bytes, parsing it into a U384, and then adding back one
  let mut modulus = [0; L];
  // The byte repr of scalars will be 32 big-endian bytes
  // Set the lower 32 bytes of our 48-byte array accordingly
  modulus[16 ..].copy_from_slice(&(C::F::ZERO - C::F::ONE).to_repr());
  // Use a checked_add + unwrap since this addition cannot fail (being a 32-byte value with
  // 48-bytes of space)
  // While a non-panicking saturating_add/wrapping_add could be used, they'd likely be less
  // performant
  let modulus = U384::from_be_slice(&modulus).checked_add(&U384::ONE).unwrap();

  // The defined P-256 and secp256k1 ciphersuites both use expand_message_xmd
  let mut wide = U384::from_be_bytes({
    let mut bytes = [0; 48];
    ExpandMsgXmd::<Sha256>::expand_message(&[msg], &[dst], 48).unwrap().fill_bytes(&mut bytes);
    bytes
  })
  .rem(&NonZero::new(modulus).unwrap())
  .to_be_bytes();

  // Now that this has been reduced back to a 32-byte value, grab the lower 32-bytes
  let mut array = *GenericArray::from_slice(&wide[16 ..]);
  let res = C::F::from_repr(array).unwrap();

  // Zeroize the temp values we can due to the possibility `hash_to_F` is being used for
  // nonces
  wide.zeroize();
  array.zeroize();
  res
}

macro_rules! kp_curve {
  (
    $feature: literal,

    $Curve: ident,
    $Hram:  ident,

    $CONTEXT: literal
  ) => {
    pub use ciphersuite_kp256::$Curve;

    impl Curve for $Curve {
      const CONTEXT: &'static [u8] = $CONTEXT;

      // These ciphersuites define their hash as SHA-512, yet FROST uses SHA-256
      fn hash(dst: &[u8], data: &[u8]) -> impl AsRef<[u8]> {
        sha2::Sha256::digest([Self::CONTEXT, dst, data].concat())
      }

      fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
        let dst = [Self::CONTEXT, dst].concat();
        let dst = dst.as_slice();
        hash_to_F::<Self>(dst, msg)
      }
    }

    /// The challenge function for this ciphersuite.
    #[derive(Clone)]
    pub struct $Hram;
    impl Hram<$Curve> for $Hram {
      #[expect(non_snake_case)]
      fn hram(
        R: &<$Curve as WrappedGroup>::G,
        A: &<$Curve as WrappedGroup>::G,
        m: &[u8],
      ) -> <$Curve as WrappedGroup>::F {
        <$Curve as Curve>::hash_to_F(
          b"chal",
          &[R.to_bytes().as_ref(), A.to_bytes().as_ref(), m].concat(),
        )
      }
    }
  };
}

#[cfg(feature = "p256")]
kp_curve!("p256", P256, IrtfP256Hram, b"FROST-P256-SHA256-v1");

#[cfg(feature = "secp256k1")]
kp_curve!("secp256k1", Secp256k1, IrtfSecp256k1Hram, b"FROST-secp256k1-SHA256-v1");

#[cfg(test)]
fn test_oversize_dst<C: WrappedGroup<F: PrimeField<Repr = GenericArray<u8, U32>>>>() {
  use sha2::Digest as _;

  // The draft specifies DSTs >255 bytes should be hashed into a 32-byte DST
  let oversize_dst = [0x00; 256];
  let actual_dst = Sha256::digest([b"H2C-OVERSIZE-DST-".as_slice(), &oversize_dst].concat());
  // Test the hash_to_F function handles this
  // If it didn't, these would return different values
  assert_eq!(hash_to_F::<C>(&oversize_dst, &[]), hash_to_F::<C>(&actual_dst, &[]));
}

#[cfg(feature = "secp256k1")]
#[test]
fn test_secp256k1() {
  test_oversize_dst::<Secp256k1>();
}

#[cfg(feature = "p256")]
#[test]
fn test_p256() {
  test_oversize_dst::<P256>();
}

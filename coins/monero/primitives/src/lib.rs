#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use std_shims::{vec, vec::Vec};
#[cfg(feature = "std")]
use std_shims::sync::OnceLock;

use zeroize::{Zeroize, ZeroizeOnDrop};

use sha3::{Digest, Keccak256};
use curve25519_dalek::{
  constants::ED25519_BASEPOINT_POINT,
  traits::VartimePrecomputedMultiscalarMul,
  scalar::Scalar,
  edwards::{EdwardsPoint, VartimeEdwardsPrecomputation},
};

use monero_io::varint_len;
use monero_generators::H;

// TODO: Replace this with a const
#[cfg(feature = "std")]
static INV_EIGHT_CELL: OnceLock<Scalar> = OnceLock::new();
#[cfg(feature = "std")]
#[allow(non_snake_case)]
pub fn INV_EIGHT() -> Scalar {
  *INV_EIGHT_CELL.get_or_init(|| Scalar::from(8u8).invert())
}
#[cfg(not(feature = "std"))]
#[allow(non_snake_case)]
pub fn INV_EIGHT() -> Scalar {
  Scalar::from(8u8).invert()
}

// On std, we cache this in a static
// In no-std environments, we prefer the reduced memory use and calculate it ad-hoc
#[cfg(feature = "std")]
static BASEPOINT_PRECOMP_CELL: OnceLock<VartimeEdwardsPrecomputation> = OnceLock::new();
#[cfg(feature = "std")]
#[allow(non_snake_case)]
pub fn BASEPOINT_PRECOMP() -> &'static VartimeEdwardsPrecomputation {
  BASEPOINT_PRECOMP_CELL
    .get_or_init(|| VartimeEdwardsPrecomputation::new([ED25519_BASEPOINT_POINT]))
}
#[cfg(not(feature = "std"))]
#[allow(non_snake_case)]
pub fn BASEPOINT_PRECOMP() -> VartimeEdwardsPrecomputation {
  VartimeEdwardsPrecomputation::new([ED25519_BASEPOINT_POINT])
}

pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
  Keccak256::digest(data.as_ref()).into()
}

/// Hash the provided data to a scalar via keccak256(data) % l.
pub fn keccak256_to_scalar(data: impl AsRef<[u8]>) -> Scalar {
  let scalar = Scalar::from_bytes_mod_order(keccak256(data.as_ref()));
  // Monero will explicitly error in this case
  // This library acknowledges its practical impossibility of it occurring, and doesn't bother to
  // code in logic to handle it. That said, if it ever occurs, something must happen in order to
  // not generate/verify a proof we believe to be valid when it isn't
  assert!(scalar != Scalar::ZERO, "ZERO HASH: {:?}", data.as_ref());
  scalar
}

/// Transparent structure representing a Pedersen commitment's contents.
#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Commitment {
  pub mask: Scalar,
  pub amount: u64,
}

impl core::fmt::Debug for Commitment {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("Commitment").field("amount", &self.amount).finish_non_exhaustive()
  }
}

impl Commitment {
  /// A commitment to zero, defined with a mask of 1 (as to not be the identity).
  pub fn zero() -> Commitment {
    Commitment { mask: Scalar::ONE, amount: 0 }
  }

  pub fn new(mask: Scalar, amount: u64) -> Commitment {
    Commitment { mask, amount }
  }

  /// Calculate a Pedersen commitment, as a point, from the transparent structure.
  pub fn calculate(&self) -> EdwardsPoint {
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&Scalar::from(self.amount), &H(), &self.mask)
  }
}

/// Decoy data, containing the actual member as well (at index `i`).
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Decoys {
  pub i: u8,
  pub offsets: Vec<u64>,
  pub ring: Vec<[EdwardsPoint; 2]>,
}

#[allow(clippy::len_without_is_empty)]
impl Decoys {
  pub fn fee_weight(offsets: &[u64]) -> usize {
    varint_len(offsets.len()) + offsets.iter().map(|offset| varint_len(*offset)).sum::<usize>()
  }

  pub fn len(&self) -> usize {
    self.offsets.len()
  }

  pub fn indexes(&self) -> Vec<u64> {
    let mut res = vec![self.offsets[0]; self.len()];
    for m in 1 .. res.len() {
      res[m] = res[m - 1] + self.offsets[m];
    }
    res
  }
}

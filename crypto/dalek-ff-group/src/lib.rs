#![allow(deprecated)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std] // Prevents writing new code, in what should be a simple wrapper, which requires std
#![doc = include_str!("../README.md")]
#![allow(clippy::redundant_closure_call)]

use core::{
  borrow::Borrow,
  ops::{Deref, Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign},
  iter::{Iterator, Sum},
};

use zeroize::Zeroize;
use subtle::{ConstantTimeEq, ConditionallySelectable};

use rand_core::RngCore;

use subtle::{Choice, CtOption};

use curve25519_dalek::{
  edwards::{EdwardsPoint as DEdwardsPoint, CompressedEdwardsY},
};
pub use curve25519_dalek::{Scalar, ristretto::RistrettoPoint};

use ::ciphersuite::group::{Group, GroupEncoding, prime::PrimeGroup};

mod ciphersuite;
pub use crate::ciphersuite::{Ed25519, Ristretto};

use core::hint::black_box;

fn u8_from_bool(bit_ref: &mut bool) -> u8 {
  let bit_ref = black_box(bit_ref);

  let mut bit = black_box(*bit_ref);
  #[allow(clippy::cast_lossless)]
  let res = black_box(bit as u8);
  bit.zeroize();
  debug_assert!((res | 1) == 1);

  bit_ref.zeroize();
  res
}

// Convert a boolean to a Choice in a *presumably* constant time manner
fn choice(mut value: bool) -> Choice {
  Choice::from(u8_from_bool(&mut value))
}

macro_rules! deref_borrow {
  ($Source: ident, $Target: ident) => {
    impl Deref for $Source {
      type Target = $Target;

      fn deref(&self) -> &Self::Target {
        &self.0
      }
    }

    impl Borrow<$Target> for $Source {
      fn borrow(&self) -> &$Target {
        &self.0
      }
    }

    impl Borrow<$Target> for &$Source {
      fn borrow(&self) -> &$Target {
        &self.0
      }
    }
  };
}

macro_rules! constant_time {
  ($Value: ident, $Inner: ident) => {
    impl ConstantTimeEq for $Value {
      fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
      }
    }

    impl ConditionallySelectable for $Value {
      fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        $Value($Inner::conditional_select(&a.0, &b.0, choice))
      }
    }
  };
}

macro_rules! math_op_without_wrapping {
  (
    $Value: ident,
    $Other: ident,
    $Op: ident,
    $op_fn: ident,
    $Assign: ident,
    $assign_fn: ident,
    $function: expr
  ) => {
    impl $Op<$Other> for $Value {
      type Output = $Value;
      fn $op_fn(self, other: $Other) -> Self::Output {
        Self($function(self.0, other))
      }
    }
    impl $Assign<$Other> for $Value {
      fn $assign_fn(&mut self, other: $Other) {
        self.0 = $function(self.0, other);
      }
    }
    impl<'a> $Op<&'a $Other> for $Value {
      type Output = $Value;
      fn $op_fn(self, other: &'a $Other) -> Self::Output {
        Self($function(self.0, other))
      }
    }
    impl<'a> $Assign<&'a $Other> for $Value {
      fn $assign_fn(&mut self, other: &'a $Other) {
        self.0 = $function(self.0, other);
      }
    }
  };
}

macro_rules! math_op {
  (
    $Value: ident,
    $Other: ident,
    $Op: ident,
    $op_fn: ident,
    $Assign: ident,
    $assign_fn: ident,
    $function: expr
  ) => {
    impl $Op<$Other> for $Value {
      type Output = $Value;
      fn $op_fn(self, other: $Other) -> Self::Output {
        Self($function(self.0, other.0))
      }
    }
    impl $Assign<$Other> for $Value {
      fn $assign_fn(&mut self, other: $Other) {
        self.0 = $function(self.0, other.0);
      }
    }
    impl<'a> $Op<&'a $Other> for $Value {
      type Output = $Value;
      fn $op_fn(self, other: &'a $Other) -> Self::Output {
        Self($function(self.0, other.0))
      }
    }
    impl<'a> $Assign<&'a $Other> for $Value {
      fn $assign_fn(&mut self, other: &'a $Other) {
        self.0 = $function(self.0, other.0);
      }
    }
  };
}

macro_rules! math_neg {
  ($Value: ident, $Factor: ident, $add: expr, $sub: expr, $mul: expr) => {
    math_op!($Value, $Value, Add, add, AddAssign, add_assign, $add);
    math_op!($Value, $Value, Sub, sub, SubAssign, sub_assign, $sub);
    math_op_without_wrapping!($Value, $Factor, Mul, mul, MulAssign, mul_assign, $mul);

    impl Neg for $Value {
      type Output = Self;
      fn neg(self) -> Self::Output {
        Self(-self.0)
      }
    }
  };
}

macro_rules! dalek_group {
  (
    $Point: ident,
    $DPoint: ident,
    $torsion_free: expr,

    $Table: ident,

    $DCompressed: ident,
  ) => {
    /// Wrapper around the dalek Point type.
    ///
    /// All operations will be restricted to a prime-order subgroup (equivalent to the group itself
    /// in the case of Ristretto). The exposure of the internal element does allow bypassing this
    /// however, which may lead to undefined/computationally-unsafe behavior, and is entirely at
    /// the user's risk.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
    pub struct $Point(pub $DPoint);
    deref_borrow!($Point, $DPoint);
    constant_time!($Point, $DPoint);
    math_neg!($Point, Scalar, $DPoint::add, $DPoint::sub, $DPoint::mul);

    impl Sum<$Point> for $Point {
      fn sum<I: Iterator<Item = $Point>>(iter: I) -> $Point {
        Self($DPoint::sum(iter))
      }
    }
    impl<'a> Sum<&'a $Point> for $Point {
      fn sum<I: Iterator<Item = &'a $Point>>(iter: I) -> $Point {
        Self($DPoint::sum(iter))
      }
    }

    impl Group for $Point {
      type Scalar = Scalar;
      fn random(mut rng: impl RngCore) -> Self {
        loop {
          let mut bytes = [0; 32];
          rng.fill_bytes(&mut bytes);
          let Some(point) = Option::<$Point>::from($Point::from_bytes(&bytes)) else {
            continue;
          };
          // Ban identity, per the trait specification
          if !bool::from(point.is_identity()) {
            return point;
          }
        }
      }
      fn identity() -> Self {
        Self($DPoint::identity())
      }
      fn generator() -> Self {
        Self(<$DPoint as Group>::generator())
      }
      fn is_identity(&self) -> Choice {
        self.0.ct_eq(&$DPoint::identity())
      }
      fn double(&self) -> Self {
        Self(self.0.double())
      }
    }

    impl GroupEncoding for $Point {
      type Repr = [u8; 32];

      fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let decompressed = $DCompressed(*bytes).decompress();
        // TODO: Same note on unwrap_or as above
        let point = decompressed.unwrap_or($DPoint::identity());
        CtOption::new(
          $Point(point),
          choice(black_box(decompressed).is_some()) & choice($torsion_free(point)),
        )
      }

      fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        $Point::from_bytes(bytes)
      }

      fn to_bytes(&self) -> Self::Repr {
        self.0.to_bytes()
      }
    }

    impl PrimeGroup for $Point {}
  };
}

dalek_group!(
  EdwardsPoint,
  DEdwardsPoint,
  |point: DEdwardsPoint| point.is_torsion_free(),
  EdwardsBasepointTable,
  CompressedEdwardsY,
);

#[test]
fn test_ed25519_group() {
  ff_group_tests::group::test_prime_group_bits::<_, EdwardsPoint>(&mut rand_core::OsRng);
}

#[test]
fn test_ristretto_group() {
  ff_group_tests::group::test_prime_group_bits::<_, RistrettoPoint>(&mut rand_core::OsRng);
}

type ThirtyTwoArray = [u8; 32];
prime_field::odd_prime_field_with_specific_repr!(
  FieldElement,
  "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
  "02",
  false,
  crate::ThirtyTwoArray
);

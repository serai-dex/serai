#![allow(deprecated)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![no_std] // Prevents writing new code, in what should be a simple wrapper, which requires std
#![doc = include_str!("../README.md")]
#![allow(clippy::redundant_closure_call)]

use core::{
  borrow::Borrow,
  ops::{Deref, Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign},
  iter::{Iterator, Sum, Product},
  hash::{Hash, Hasher},
};

use zeroize::Zeroize;
use subtle::{ConstantTimeEq, ConditionallySelectable};

use rand_core::RngCore;
use digest::{consts::U64, Digest, HashMarker};

use subtle::{Choice, CtOption};

pub use curve25519_dalek as dalek;

use dalek::{
  constants,
  scalar::Scalar as DScalar,
  edwards::{EdwardsPoint as DEdwardsPoint, EdwardsBasepointTable, CompressedEdwardsY},
  ristretto::{RistrettoPoint as DRistrettoPoint, RistrettoBasepointTable, CompressedRistretto},
};
pub use constants::{ED25519_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_TABLE};

use group::{
  ff::{Field, PrimeField, FieldBits, PrimeFieldBits},
  Group, GroupEncoding,
  prime::PrimeGroup,
};

mod field;
pub use field::FieldElement;

// Use black_box when possible
#[rustversion::since(1.66)]
use core::hint::black_box;
#[rustversion::before(1.66)]
fn black_box<T>(val: T) -> T {
  val
}

fn u8_from_bool(bit_ref: &mut bool) -> u8 {
  let bit_ref = black_box(bit_ref);

  let mut bit = black_box(*bit_ref);
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
pub(crate) use constant_time;

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
pub(crate) use math_op;

macro_rules! math {
  ($Value: ident, $Factor: ident, $add: expr, $sub: expr, $mul: expr) => {
    math_op!($Value, $Value, Add, add, AddAssign, add_assign, $add);
    math_op!($Value, $Value, Sub, sub, SubAssign, sub_assign, $sub);
    math_op!($Value, $Factor, Mul, mul, MulAssign, mul_assign, $mul);
  };
}
pub(crate) use math;

macro_rules! math_neg {
  ($Value: ident, $Factor: ident, $add: expr, $sub: expr, $mul: expr) => {
    math!($Value, $Factor, $add, $sub, $mul);

    impl Neg for $Value {
      type Output = Self;
      fn neg(self) -> Self::Output {
        Self(-self.0)
      }
    }
  };
}

/// Wrapper around the dalek Scalar type.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct Scalar(pub DScalar);
deref_borrow!(Scalar, DScalar);
constant_time!(Scalar, DScalar);
math_neg!(Scalar, Scalar, DScalar::add, DScalar::sub, DScalar::mul);

macro_rules! from_wrapper {
  ($uint: ident) => {
    impl From<$uint> for Scalar {
      fn from(a: $uint) -> Scalar {
        Scalar(DScalar::from(a))
      }
    }
  };
}

from_wrapper!(u8);
from_wrapper!(u16);
from_wrapper!(u32);
from_wrapper!(u64);
from_wrapper!(u128);

impl Scalar {
  pub fn pow(&self, other: Scalar) -> Scalar {
    let mut table = [Scalar::ONE; 16];
    table[1] = *self;
    for i in 2 .. 16 {
      table[i] = table[i - 1] * self;
    }

    let mut res = Scalar::ONE;
    let mut bits = 0;
    for (i, mut bit) in other.to_le_bits().iter_mut().rev().enumerate() {
      bits <<= 1;
      let mut bit = u8_from_bool(&mut bit);
      bits |= bit;
      bit.zeroize();

      if ((i + 1) % 4) == 0 {
        if i != 3 {
          for _ in 0 .. 4 {
            res *= res;
          }
        }
        res *= table[usize::from(bits)];
        bits = 0;
      }
    }
    res
  }

  /// Perform wide reduction on a 64-byte array to create a Scalar without bias.
  pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Scalar {
    Self(DScalar::from_bytes_mod_order_wide(bytes))
  }

  /// Derive a Scalar without bias from a digest via wide reduction.
  pub fn from_hash<D: Digest<OutputSize = U64> + HashMarker>(hash: D) -> Scalar {
    let mut output = [0u8; 64];
    output.copy_from_slice(&hash.finalize());
    let res = Scalar(DScalar::from_bytes_mod_order_wide(&output));
    output.zeroize();
    res
  }
}

impl Field for Scalar {
  const ZERO: Scalar = Scalar(DScalar::ZERO);
  const ONE: Scalar = Scalar(DScalar::ONE);

  fn random(rng: impl RngCore) -> Self {
    Self(<DScalar as Field>::random(rng))
  }

  fn square(&self) -> Self {
    Self(self.0.square())
  }
  fn double(&self) -> Self {
    Self(self.0.double())
  }
  fn invert(&self) -> CtOption<Self> {
    <DScalar as Field>::invert(&self.0).map(Self)
  }

  fn sqrt(&self) -> CtOption<Self> {
    self.0.sqrt().map(Self)
  }

  fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
    let (choice, res) = DScalar::sqrt_ratio(num, div);
    (choice, Self(res))
  }
}

impl PrimeField for Scalar {
  type Repr = [u8; 32];

  const MODULUS: &'static str = <DScalar as PrimeField>::MODULUS;

  const NUM_BITS: u32 = <DScalar as PrimeField>::NUM_BITS;
  const CAPACITY: u32 = <DScalar as PrimeField>::CAPACITY;

  const TWO_INV: Scalar = Scalar(<DScalar as PrimeField>::TWO_INV);

  const MULTIPLICATIVE_GENERATOR: Scalar =
    Scalar(<DScalar as PrimeField>::MULTIPLICATIVE_GENERATOR);
  const S: u32 = <DScalar as PrimeField>::S;

  const ROOT_OF_UNITY: Scalar = Scalar(<DScalar as PrimeField>::ROOT_OF_UNITY);
  const ROOT_OF_UNITY_INV: Scalar = Scalar(<DScalar as PrimeField>::ROOT_OF_UNITY_INV);

  const DELTA: Scalar = Scalar(<DScalar as PrimeField>::DELTA);

  fn from_repr(bytes: [u8; 32]) -> CtOption<Self> {
    <DScalar as PrimeField>::from_repr(bytes).map(Scalar)
  }
  fn to_repr(&self) -> [u8; 32] {
    self.0.to_repr()
  }

  fn is_odd(&self) -> Choice {
    self.0.is_odd()
  }

  fn from_u128(num: u128) -> Self {
    Scalar(DScalar::from_u128(num))
  }
}

impl PrimeFieldBits for Scalar {
  type ReprBits = [u8; 32];

  fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
    self.to_repr().into()
  }

  fn char_le_bits() -> FieldBits<Self::ReprBits> {
    let mut bytes = (Scalar::ZERO - Scalar::ONE).to_repr();
    bytes[0] += 1;
    debug_assert_eq!(DScalar::from_bytes_mod_order(bytes), DScalar::ZERO);
    bytes.into()
  }
}

impl Sum<Scalar> for Scalar {
  fn sum<I: Iterator<Item = Scalar>>(iter: I) -> Scalar {
    Self(DScalar::sum(iter))
  }
}

impl<'a> Sum<&'a Scalar> for Scalar {
  fn sum<I: Iterator<Item = &'a Scalar>>(iter: I) -> Scalar {
    Self(DScalar::sum(iter))
  }
}

impl Product<Scalar> for Scalar {
  fn product<I: Iterator<Item = Scalar>>(iter: I) -> Scalar {
    Self(DScalar::product(iter))
  }
}

impl<'a> Product<&'a Scalar> for Scalar {
  fn product<I: Iterator<Item = &'a Scalar>>(iter: I) -> Scalar {
    Self(DScalar::product(iter))
  }
}

macro_rules! dalek_group {
  (
    $Point: ident,
    $DPoint: ident,
    $torsion_free: expr,

    $Table: ident,

    $DCompressed: ident,

    $BASEPOINT_POINT: ident,
    $BASEPOINT_TABLE: ident
  ) => {
    /// Wrapper around the dalek Point type. For Ed25519, this is restricted to the prime subgroup.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
    pub struct $Point(pub $DPoint);
    deref_borrow!($Point, $DPoint);
    constant_time!($Point, $DPoint);
    math_neg!($Point, Scalar, $DPoint::add, $DPoint::sub, $DPoint::mul);

    /// The basepoint for this curve.
    pub const $BASEPOINT_POINT: $Point = $Point(constants::$BASEPOINT_POINT);

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
        $BASEPOINT_POINT
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

    impl Mul<Scalar> for &$Table {
      type Output = $Point;
      fn mul(self, b: Scalar) -> $Point {
        $Point(&b.0 * self)
      }
    }

    // Support being used as a key in a table
    // While it is expensive as a key, due to the field operations required, there's frequently
    // use cases for public key -> value lookups
    #[allow(unknown_lints, renamed_and_removed_lints)]
    #[allow(clippy::derived_hash_with_manual_eq, clippy::derive_hash_xor_eq)]
    impl Hash for $Point {
      fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
      }
    }
  };
}

dalek_group!(
  EdwardsPoint,
  DEdwardsPoint,
  |point: DEdwardsPoint| point.is_torsion_free(),
  EdwardsBasepointTable,
  CompressedEdwardsY,
  ED25519_BASEPOINT_POINT,
  ED25519_BASEPOINT_TABLE
);

impl EdwardsPoint {
  pub fn mul_by_cofactor(&self) -> EdwardsPoint {
    EdwardsPoint(self.0.mul_by_cofactor())
  }
}

dalek_group!(
  RistrettoPoint,
  DRistrettoPoint,
  |_| true,
  RistrettoBasepointTable,
  CompressedRistretto,
  RISTRETTO_BASEPOINT_POINT,
  RISTRETTO_BASEPOINT_TABLE
);

#[test]
fn test_ed25519_group() {
  ff_group_tests::group::test_prime_group_bits::<_, EdwardsPoint>(&mut rand_core::OsRng);
}

#[test]
fn test_ristretto_group() {
  ff_group_tests::group::test_prime_group_bits::<_, RistrettoPoint>(&mut rand_core::OsRng);
}

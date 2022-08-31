#![no_std]

use core::{
  ops::{Deref, Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign},
  borrow::Borrow,
  iter::{Iterator, Sum},
};

use zeroize::Zeroize;
use subtle::{ConstantTimeEq, ConditionallySelectable};

use rand_core::RngCore;
use digest::{consts::U64, Digest};

use subtle::{Choice, CtOption};

pub use curve25519_dalek as dalek;

use dalek::{
  constants,
  traits::Identity,
  scalar::Scalar as DScalar,
  edwards::{
    EdwardsPoint as DEdwardsPoint, EdwardsBasepointTable as DEdwardsBasepointTable,
    CompressedEdwardsY as DCompressedEdwards,
  },
  ristretto::{
    RistrettoPoint as DRistrettoPoint, RistrettoBasepointTable as DRistrettoBasepointTable,
    CompressedRistretto as DCompressedRistretto,
  },
};

use ff::{Field, PrimeField, FieldBits, PrimeFieldBits};
use group::{Group, GroupEncoding, prime::PrimeGroup};

pub mod field;

// Convert a boolean to a Choice in a *presumably* constant time manner
fn choice(value: bool) -> Choice {
  let bit = value as u8;
  debug_assert_eq!(bit | 1, 1);
  Choice::from(bit)
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

#[doc(hidden)]
#[macro_export]
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

#[doc(hidden)]
#[macro_export]
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

#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! math {
  ($Value: ident, $Factor: ident, $add: expr, $sub: expr, $mul: expr) => {
    math_op!($Value, $Value, Add, add, AddAssign, add_assign, $add);
    math_op!($Value, $Value, Sub, sub, SubAssign, sub_assign, $sub);
    math_op!($Value, $Factor, Mul, mul, MulAssign, mul_assign, $mul);
  };
}

#[doc(hidden)]
#[macro_export(local_inner_macros)]
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

#[doc(hidden)]
#[macro_export]
macro_rules! from_wrapper {
  ($wrapper: ident, $inner: ident, $uint: ident) => {
    impl From<$uint> for $wrapper {
      fn from(a: $uint) -> $wrapper {
        Self($inner::from(a))
      }
    }
  };
}

#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! from_uint {
  ($wrapper: ident, $inner: ident) => {
    from_wrapper!($wrapper, $inner, u8);
    from_wrapper!($wrapper, $inner, u16);
    from_wrapper!($wrapper, $inner, u32);
    from_wrapper!($wrapper, $inner, u64);
  };
}

/// Wrapper around the dalek Scalar type
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct Scalar(pub DScalar);
deref_borrow!(Scalar, DScalar);
constant_time!(Scalar, DScalar);
math_neg!(Scalar, Scalar, DScalar::add, DScalar::sub, DScalar::mul);
from_uint!(Scalar, DScalar);

impl Scalar {
  /// Perform wide reduction on a 64-byte array to create a Scalar without bias
  pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Scalar {
    Self(DScalar::from_bytes_mod_order_wide(bytes))
  }

  /// Derive a Scalar without bias from a digest via wide reduction
  pub fn from_hash<D: Digest<OutputSize = U64>>(hash: D) -> Scalar {
    let mut output = [0u8; 64];
    output.copy_from_slice(&hash.finalize());
    let res = Scalar(DScalar::from_bytes_mod_order_wide(&output));
    output.zeroize();
    res
  }
}

impl Field for Scalar {
  fn random(mut rng: impl RngCore) -> Self {
    let mut r = [0; 64];
    rng.fill_bytes(&mut r);
    Self(DScalar::from_bytes_mod_order_wide(&r))
  }

  fn zero() -> Self {
    Self(DScalar::zero())
  }
  fn one() -> Self {
    Self(DScalar::one())
  }
  fn square(&self) -> Self {
    *self * self
  }
  fn double(&self) -> Self {
    *self + self
  }
  fn invert(&self) -> CtOption<Self> {
    CtOption::new(Self(self.0.invert()), !self.is_zero())
  }
  fn sqrt(&self) -> CtOption<Self> {
    unimplemented!()
  }
  fn is_zero(&self) -> Choice {
    self.0.ct_eq(&DScalar::zero())
  }
  fn cube(&self) -> Self {
    *self * self * self
  }
  fn pow_vartime<S: AsRef<[u64]>>(&self, _exp: S) -> Self {
    unimplemented!()
  }
}

impl PrimeField for Scalar {
  type Repr = [u8; 32];
  const NUM_BITS: u32 = 253;
  const CAPACITY: u32 = 252;
  fn from_repr(bytes: [u8; 32]) -> CtOption<Self> {
    let scalar = DScalar::from_canonical_bytes(bytes);
    // TODO: This unwrap_or isn't constant time, yet do we have an alternative?
    CtOption::new(Scalar(scalar.unwrap_or_else(DScalar::zero)), choice(scalar.is_some()))
  }
  fn to_repr(&self) -> [u8; 32] {
    self.0.to_bytes()
  }

  const S: u32 = 2;
  fn is_odd(&self) -> Choice {
    choice(self.to_le_bits()[0])
  }
  fn multiplicative_generator() -> Self {
    2u64.into()
  }
  fn root_of_unity() -> Self {
    unimplemented!()
  }
}

impl PrimeFieldBits for Scalar {
  type ReprBits = [u8; 32];

  fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
    self.to_repr().into()
  }

  fn char_le_bits() -> FieldBits<Self::ReprBits> {
    let mut bytes = (Scalar::zero() - Scalar::one()).to_repr();
    bytes[0] += 1;
    debug_assert_eq!(DScalar::from_bytes_mod_order(bytes), DScalar::zero());
    bytes.into()
  }
}

impl Sum<Scalar> for Scalar {
  fn sum<I: Iterator<Item = Scalar>>(iter: I) -> Scalar {
    Self(DScalar::sum(iter))
  }
}

macro_rules! dalek_group {
  (
    $Point: ident,
    $DPoint: ident,
    $torsion_free: expr,

    $Table: ident,
    $DTable: ident,

    $DCompressed: ident,

    $BASEPOINT_POINT: ident,
    $BASEPOINT_TABLE: ident
  ) => {
    /// Wrapper around the dalek Point type. For Ed25519, this is restricted to the prime subgroup
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
    pub struct $Point(pub $DPoint);
    deref_borrow!($Point, $DPoint);
    constant_time!($Point, $DPoint);
    math_neg!($Point, Scalar, $DPoint::add, $DPoint::sub, $DPoint::mul);

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
          let mut bytes = field::FieldElement::random(&mut rng).to_repr();
          bytes[31] |= u8::try_from(rng.next_u32() % 2).unwrap() << 7;
          let opt = Self::from_bytes(&bytes);
          if opt.is_some().into() {
            return opt.unwrap();
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
        *self + self
      }
    }

    impl GroupEncoding for $Point {
      type Repr = [u8; 32];

      fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let decompressed = $DCompressed(*bytes).decompress();
        // TODO: Same note on unwrap_or as above
        let point = decompressed.unwrap_or($DPoint::identity());
        CtOption::new($Point(point), choice(decompressed.is_some()) & choice($torsion_free(point)))
      }

      fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        $Point::from_bytes(bytes)
      }

      fn to_bytes(&self) -> Self::Repr {
        self.0.compress().to_bytes()
      }
    }

    impl PrimeGroup for $Point {}

    /// Wrapper around the dalek Table type, offering efficient multiplication against the
    /// basepoint
    pub struct $Table(pub $DTable);
    deref_borrow!($Table, $DTable);
    pub const $BASEPOINT_TABLE: $Table = $Table(constants::$BASEPOINT_TABLE);

    impl Mul<Scalar> for &$Table {
      type Output = $Point;
      fn mul(self, b: Scalar) -> $Point {
        $Point(&b.0 * &self.0)
      }
    }
  };
}

dalek_group!(
  EdwardsPoint,
  DEdwardsPoint,
  |point: DEdwardsPoint| point.is_torsion_free(),
  EdwardsBasepointTable,
  DEdwardsBasepointTable,
  DCompressedEdwards,
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
  DRistrettoBasepointTable,
  DCompressedRistretto,
  RISTRETTO_BASEPOINT_POINT,
  RISTRETTO_BASEPOINT_TABLE
);

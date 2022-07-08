#![no_std]

use core::{
  ops::{Deref, Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign},
  borrow::Borrow,
  iter::{Iterator, Sum}
};

use rand_core::RngCore;
use digest::{consts::U64, Digest};

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

pub use curve25519_dalek as dalek;

use dalek::{
  constants,
  traits::Identity,
  scalar::Scalar as DScalar,
  edwards::{
    EdwardsPoint as DEdwardsPoint,
    EdwardsBasepointTable as DEdwardsBasepointTable,
    CompressedEdwardsY as DCompressedEdwards
  },
  ristretto::{
    RistrettoPoint as DRistrettoPoint,
    RistrettoBasepointTable as DRistrettoBasepointTable,
    CompressedRistretto as DCompressedRistretto
  }
};

use ff::{Field, PrimeField, FieldBits, PrimeFieldBits};
use group::{Group, GroupEncoding, prime::PrimeGroup};

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
  }
}

macro_rules! math {
  ($Value: ident, $Factor: ident, $Product: ident) => {
    impl Add<$Value> for $Value {
      type Output = Self;
      fn add(self, other: $Value) -> Self::Output { Self(self.0 + other.0) }
    }
    impl AddAssign for $Value {
      fn add_assign(&mut self, other: $Value) { self.0 += other.0 }
    }

    impl<'a> Add<&'a $Value> for $Value {
      type Output = Self;
      fn add(self, other: &'a $Value) -> Self::Output { Self(self.0 + other.0) }
    }
    impl<'a> AddAssign<&'a $Value> for $Value {
      fn add_assign(&mut self, other: &'a $Value) { self.0 += other.0 }
    }

    impl Sub<$Value> for $Value {
      type Output = Self;
      fn sub(self, other: $Value) -> Self::Output { Self(self.0 - other.0) }
    }
    impl SubAssign for $Value {
      fn sub_assign(&mut self, other: $Value) { self.0 -= other.0 }
    }

    impl<'a> Sub<&'a $Value> for $Value {
      type Output = Self;
      fn sub(self, other: &'a $Value) -> Self::Output { Self(self.0 - other.0) }
    }
    impl<'a> SubAssign<&'a $Value> for $Value {
      fn sub_assign(&mut self, other: &'a $Value) { self.0 -= other.0 }
    }

    impl Neg for $Value {
      type Output = Self;
      fn neg(self) -> Self::Output { Self(-self.0) }
    }

    impl Mul<$Factor> for $Value {
      type Output = $Product;
      fn mul(self, other: $Factor) -> Self::Output { Self(self.0 * other.0) }
    }
    impl MulAssign<$Factor> for $Value {
      fn mul_assign(&mut self, other: $Factor) { self.0 *= other.0 }
    }

    impl<'a> Mul<&'a $Factor> for $Value {
      type Output = Self;
      fn mul(self, b: &'a $Factor) -> $Product { Self(b.0 * self.0) }
    }
    impl<'a> MulAssign<&'a $Factor> for $Value {
      fn mul_assign(&mut self, other: &'a $Factor) { self.0 *= other.0 }
    }
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Scalar(pub DScalar);
deref_borrow!(Scalar, DScalar);
math!(Scalar, Scalar, Scalar);

impl Scalar {
  pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Scalar> {
    DScalar::from_canonical_bytes(bytes).map(|x| Self(x))
  }

  pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Scalar {
    Self(DScalar::from_bytes_mod_order(bytes))
  }

  pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Scalar {
    Self(DScalar::from_bytes_mod_order_wide(bytes))
  }

  pub fn from_hash<D: Digest<OutputSize = U64>>(hash: D) -> Scalar {
    let mut output = [0u8; 64];
    output.copy_from_slice(&hash.finalize());
    Scalar(DScalar::from_bytes_mod_order_wide(&output))
  }
}

impl ConstantTimeEq for Scalar {
  fn ct_eq(&self, other: &Self) -> Choice { self.0.ct_eq(&other.0) }
}

impl ConditionallySelectable for Scalar {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    Scalar(DScalar::conditional_select(a, b, choice))
  }
}

impl Field for Scalar {
  fn random(mut rng: impl RngCore) -> Self {
    let mut r = [0; 64];
    rng.fill_bytes(&mut r);
    Self(DScalar::from_bytes_mod_order_wide(&r))
  }

  fn zero() -> Self { Self(DScalar::zero()) }
  fn one() -> Self { Self(DScalar::one()) }
  fn square(&self) -> Self { *self * self }
  fn double(&self) -> Self { *self + self }
  fn invert(&self) -> CtOption<Self> {
    CtOption::new(Self(self.0.invert()), self.is_zero())
  }
  fn sqrt(&self) -> CtOption<Self> { unimplemented!() }
  fn is_zero(&self) -> Choice { self.0.ct_eq(&DScalar::zero()) }
  fn cube(&self) -> Self { *self * self * self }
  fn pow_vartime<S: AsRef<[u64]>>(&self, _exp: S) -> Self { unimplemented!() }
}

impl From<u64> for Scalar {
  fn from(a: u64) -> Scalar { Self(DScalar::from(a)) }
}

impl PrimeField for Scalar {
  type Repr = [u8; 32];
  const NUM_BITS: u32 = 253;
  const CAPACITY: u32 = 252;
  fn from_repr(bytes: [u8; 32]) -> CtOption<Self> {
    let scalar = DScalar::from_canonical_bytes(bytes);
    // TODO: This unwrap_or isn't constant time, yet do we have an alternative?
    CtOption::new(Scalar(scalar.unwrap_or(DScalar::zero())), choice(scalar.is_some()))
  }
  fn to_repr(&self) -> [u8; 32] { self.0.to_bytes() }

  const S: u32 = 2;
  fn is_odd(&self) -> Choice { unimplemented!() }
  fn multiplicative_generator() -> Self { 2u64.into() }
  fn root_of_unity() -> Self { unimplemented!() }
}

impl PrimeFieldBits for Scalar {
  type ReprBits = [u8; 32];

  fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
    self.to_repr().into()
  }

  fn char_le_bits() -> FieldBits<Self::ReprBits> {
    let mut bytes = (Scalar::zero() - Scalar::one()).to_repr();
    bytes[0] += 1;
    debug_assert_eq!(Scalar::from_bytes_mod_order(bytes), Scalar::zero());
    bytes.into()
  }
}

macro_rules! dalek_group {
  (
    $Point: ident,
    $DPoint: ident,
    $torsion_free: expr,

    $Table: ident,
    $DTable: ident,

    $Compressed: ident,
    $DCompressed: ident,

    $BASEPOINT_POINT: ident,
    $BASEPOINT_TABLE: ident
  ) => {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct $Point(pub $DPoint);
    deref_borrow!($Point, $DPoint);
    math!($Point, Scalar, $Point);

    pub const $BASEPOINT_POINT: $Point = $Point(constants::$BASEPOINT_POINT);

    impl Sum<$Point> for $Point {
      fn sum<I: Iterator<Item = $Point>>(iter: I) -> $Point { Self($DPoint::sum(iter)) }
    }
    impl<'a> Sum<&'a $Point> for $Point {
      fn sum<I: Iterator<Item = &'a $Point>>(iter: I) -> $Point { Self($DPoint::sum(iter)) }
    }

    impl Group for $Point {
      type Scalar = Scalar;
      // Ideally, this would be cryptographically secure, yet that's not a bound on the trait
      // k256 also does this
      fn random(rng: impl RngCore) -> Self { &$BASEPOINT_TABLE * Scalar::random(rng) }
      fn identity() -> Self { Self($DPoint::identity()) }
      fn generator() -> Self { $BASEPOINT_POINT }
      fn is_identity(&self) -> Choice { self.0.ct_eq(&$DPoint::identity()) }
      fn double(&self) -> Self { *self + self }
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

    pub struct $Compressed(pub $DCompressed);
    deref_borrow!($Compressed, $DCompressed);
    impl $Compressed {
      pub fn new(y: [u8; 32]) -> $Compressed {
        Self($DCompressed(y))
      }

      pub fn decompress(&self) -> Option<$Point> {
        self.0.decompress().map(|x| $Point(x))
      }

      pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
      }
    }

    impl $Point {
      pub fn compress(&self) -> $Compressed {
        $Compressed(self.0.compress())
      }
    }

    pub struct $Table(pub $DTable);
    deref_borrow!($Table, $DTable);
    pub const $BASEPOINT_TABLE: $Table = $Table(constants::$BASEPOINT_TABLE);

    impl Mul<Scalar> for &$Table {
      type Output = $Point;
      fn mul(self, b: Scalar) -> $Point { $Point(&b.0 * &self.0) }
    }
  };
}

dalek_group!(
  EdwardsPoint,
  DEdwardsPoint,
  |point: DEdwardsPoint| point.is_torsion_free(),

  EdwardsBasepointTable,
  DEdwardsBasepointTable,

  CompressedEdwardsY,
  DCompressedEdwards,

  ED25519_BASEPOINT_POINT,
  ED25519_BASEPOINT_TABLE
);

dalek_group!(
  RistrettoPoint,
  DRistrettoPoint,
  |_| true,

  RistrettoBasepointTable,
  DRistrettoBasepointTable,

  CompressedRistretto,
  DCompressedRistretto,

  RISTRETTO_BASEPOINT_POINT,
  RISTRETTO_BASEPOINT_TABLE
);

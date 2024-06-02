use zeroize::Zeroize;

// Use black_box when possible
#[rustversion::since(1.66)]
use core::hint::black_box;
#[rustversion::before(1.66)]
fn black_box<T>(val: T) -> T {
  val
}

pub(crate) fn u8_from_bool(bit_ref: &mut bool) -> u8 {
  let bit_ref = black_box(bit_ref);

  let mut bit = black_box(*bit_ref);
  #[allow(clippy::cast_lossless)]
  let res = black_box(bit as u8);
  bit.zeroize();
  debug_assert!((res | 1) == 1);

  bit_ref.zeroize();
  res
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
        $Value($function(self.0, other.0))
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
        $Value($function(self.0, other.0))
      }
    }
    impl<'a> $Assign<&'a $Other> for $Value {
      fn $assign_fn(&mut self, other: &'a $Other) {
        self.0 = $function(self.0, other.0);
      }
    }
  };
}

macro_rules! from_wrapper {
  ($wrapper: ident, $inner: ident, $uint: ident) => {
    impl From<$uint> for $wrapper {
      fn from(a: $uint) -> $wrapper {
        $wrapper(Residue::new(&$inner::from(a)))
      }
    }
  };
}

macro_rules! field {
  (
    $FieldName: ident,
    $ResidueType: ident,

    $MODULUS_STR: ident,
    $MODULUS: ident,
    $WIDE_MODULUS: ident,

    $NUM_BITS: literal,

    $MULTIPLICATIVE_GENERATOR: literal,
    $DELTA: expr,
  ) => {
    use core::{
      ops::{Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign},
      iter::{Sum, Product},
    };

    use subtle::{Choice, CtOption, ConstantTimeEq, ConstantTimeLess, ConditionallySelectable};
    use rand_core::RngCore;

    use generic_array::{typenum::U57, GenericArray};
    use crypto_bigint::{Integer, NonZero, Encoding, impl_modulus};

    use ff::{Field, PrimeField, FieldBits, PrimeFieldBits, helpers::sqrt_ratio_generic};

    use $crate::backend::u8_from_bool;

    fn reduce(x: U896) -> U448 {
      U448::from_le_slice(&x.rem(&NonZero::new($WIDE_MODULUS).unwrap()).to_le_bytes()[.. 56])
    }

    impl ConstantTimeEq for $FieldName {
      fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
      }
    }

    impl ConditionallySelectable for $FieldName {
      fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        $FieldName(Residue::conditional_select(&a.0, &b.0, choice))
      }
    }

    math_op!($FieldName, $FieldName, Add, add, AddAssign, add_assign, |x: $ResidueType, y| x
      .add(&y));
    math_op!($FieldName, $FieldName, Sub, sub, SubAssign, sub_assign, |x: $ResidueType, y| x
      .sub(&y));
    math_op!($FieldName, $FieldName, Mul, mul, MulAssign, mul_assign, |x: $ResidueType, y| x
      .mul(&y));

    from_wrapper!($FieldName, U448, u8);
    from_wrapper!($FieldName, U448, u16);
    from_wrapper!($FieldName, U448, u32);
    from_wrapper!($FieldName, U448, u64);
    from_wrapper!($FieldName, U448, u128);

    impl Neg for $FieldName {
      type Output = $FieldName;
      fn neg(self) -> $FieldName {
        $FieldName(self.0.neg())
      }
    }

    impl<'a> Neg for &'a $FieldName {
      type Output = $FieldName;
      fn neg(self) -> Self::Output {
        (*self).neg()
      }
    }

    impl $FieldName {
      /// Perform an exponentiation.
      pub fn pow(&self, other: $FieldName) -> $FieldName {
        let mut table = [$FieldName(Residue::ONE); 16];
        table[1] = *self;
        for i in 2 .. 16 {
          table[i] = table[i - 1] * self;
        }

        let mut res = $FieldName(Residue::ONE);
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
    }

    impl Field for $FieldName {
      const ZERO: Self = $FieldName(Residue::ZERO);
      const ONE: Self = $FieldName(Residue::ONE);

      fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = [0; 112];
        rng.fill_bytes(&mut bytes);
        $FieldName(Residue::new(&reduce(U896::from_le_slice(bytes.as_ref()))))
      }

      fn square(&self) -> Self {
        *self * self
      }
      fn double(&self) -> Self {
        *self + self
      }

      fn invert(&self) -> CtOption<Self> {
        const NEG_2: $FieldName =
          $FieldName($ResidueType::sub(&$ResidueType::ZERO, &$ResidueType::new(&U448::from_u8(2))));
        CtOption::new(self.pow(NEG_2), !self.is_zero())
      }

      fn sqrt(&self) -> CtOption<Self> {
        const MOD_1_4: $FieldName = $FieldName($ResidueType::new(
          &$MODULUS.saturating_add(&U448::ONE).wrapping_div(&U448::from_u8(4)),
        ));

        let res = self.pow(MOD_1_4);
        CtOption::new(res, res.square().ct_eq(self))
      }

      fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        sqrt_ratio_generic(num, div)
      }
    }

    impl PrimeField for $FieldName {
      type Repr = GenericArray<u8, U57>;

      const MODULUS: &'static str = $MODULUS_STR;

      const NUM_BITS: u32 = $NUM_BITS;
      const CAPACITY: u32 = $NUM_BITS - 1;

      const TWO_INV: Self = $FieldName($ResidueType::new(&U448::from_u8(2)).invert().0);

      const MULTIPLICATIVE_GENERATOR: Self =
        $FieldName(Residue::new(&U448::from_u8($MULTIPLICATIVE_GENERATOR)));
      // True for both the Ed448 Scalar field and FieldElement field
      const S: u32 = 1;

      // Both fields have their root of unity as -1
      const ROOT_OF_UNITY: Self =
        $FieldName($ResidueType::sub(&$ResidueType::ZERO, &$ResidueType::new(&U448::ONE)));
      const ROOT_OF_UNITY_INV: Self = $FieldName(Self::ROOT_OF_UNITY.0.invert().0);

      const DELTA: Self = $FieldName(Residue::new(&U448::from_le_hex($DELTA)));

      fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
        let res = U448::from_le_slice(&bytes[.. 56]);
        CtOption::new($FieldName(Residue::new(&res)), res.ct_lt(&$MODULUS) & bytes[56].ct_eq(&0))
      }
      fn to_repr(&self) -> Self::Repr {
        let mut repr = GenericArray::<u8, U57>::default();
        repr[.. 56].copy_from_slice(&self.0.retrieve().to_le_bytes());
        repr
      }

      fn is_odd(&self) -> Choice {
        self.0.retrieve().is_odd()
      }
    }

    impl PrimeFieldBits for $FieldName {
      type ReprBits = [u8; 56];

      fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
        let mut repr = [0; 56];
        repr.copy_from_slice(&self.to_repr()[.. 56]);
        repr.into()
      }

      fn char_le_bits() -> FieldBits<Self::ReprBits> {
        let mut repr = [0; 56];
        repr.copy_from_slice(&MODULUS.to_le_bytes()[.. 56]);
        repr.into()
      }
    }

    impl Sum<$FieldName> for $FieldName {
      fn sum<I: Iterator<Item = $FieldName>>(iter: I) -> $FieldName {
        let mut res = $FieldName::ZERO;
        for item in iter {
          res += item;
        }
        res
      }
    }

    impl<'a> Sum<&'a $FieldName> for $FieldName {
      fn sum<I: Iterator<Item = &'a $FieldName>>(iter: I) -> $FieldName {
        iter.cloned().sum()
      }
    }

    impl Product<$FieldName> for $FieldName {
      fn product<I: Iterator<Item = $FieldName>>(iter: I) -> $FieldName {
        let mut res = $FieldName::ONE;
        for item in iter {
          res *= item;
        }
        res
      }
    }

    impl<'a> Product<&'a $FieldName> for $FieldName {
      fn product<I: Iterator<Item = &'a $FieldName>>(iter: I) -> $FieldName {
        iter.cloned().product()
      }
    }
  };
}

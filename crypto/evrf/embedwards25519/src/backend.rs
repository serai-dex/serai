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

macro_rules! from_wrapper {
  ($wrapper: ident, $inner: ident, $uint: ident) => {
    impl From<$uint> for $wrapper {
      fn from(a: $uint) -> $wrapper {
        Self(Residue::new(&$inner::from(a)))
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
    $S: literal,
    $ROOT_OF_UNITY: literal,
    $DELTA: literal,
  ) => {
    use core::{
      ops::{DerefMut, Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign},
      iter::{Sum, Product},
    };

    use subtle::{Choice, CtOption, ConstantTimeEq, ConstantTimeLess, ConditionallySelectable};
    use rand_core::RngCore;

    use crypto_bigint::{Integer, NonZero, Encoding, impl_modulus};

    use ciphersuite::group::ff::{
      Field, PrimeField, FieldBits, PrimeFieldBits, helpers::sqrt_ratio_generic,
    };

    use $crate::backend::u8_from_bool;

    fn reduce(x: U512) -> U256 {
      U256::from_le_slice(&x.rem(&NonZero::new($WIDE_MODULUS).unwrap()).to_le_bytes()[.. 32])
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

    from_wrapper!($FieldName, U256, u8);
    from_wrapper!($FieldName, U256, u16);
    from_wrapper!($FieldName, U256, u32);
    from_wrapper!($FieldName, U256, u64);
    from_wrapper!($FieldName, U256, u128);

    impl Neg for $FieldName {
      type Output = $FieldName;
      fn neg(self) -> $FieldName {
        Self(self.0.neg())
      }
    }

    impl<'a> Neg for &'a $FieldName {
      type Output = $FieldName;
      fn neg(self) -> Self::Output {
        (*self).neg()
      }
    }

    impl $FieldName {
      /// Perform an exponentation.
      pub fn pow(&self, other: $FieldName) -> $FieldName {
        let mut table = [Self(Residue::ONE); 16];
        table[1] = *self;
        for i in 2 .. 16 {
          table[i] = table[i - 1] * self;
        }

        let mut res = Self(Residue::ONE);
        let mut bits = 0;
        for (i, mut bit) in other.to_le_bits().iter_mut().rev().enumerate() {
          bits <<= 1;
          let mut bit = u8_from_bool(bit.deref_mut());
          bits |= bit;
          bit.zeroize();

          if ((i + 1) % 4) == 0 {
            if i != 3 {
              for _ in 0 .. 4 {
                res *= res;
              }
            }

            let mut factor = table[0];
            for (j, candidate) in table[1 ..].iter().enumerate() {
              let j = j + 1;
              factor = Self::conditional_select(&factor, &candidate, usize::from(bits).ct_eq(&j));
            }
            res *= factor;
            bits = 0;
          }
        }
        res
      }
    }

    impl Field for $FieldName {
      const ZERO: Self = Self(Residue::ZERO);
      const ONE: Self = Self(Residue::ONE);

      fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        $FieldName(Residue::new(&reduce(U512::from_le_slice(bytes.as_ref()))))
      }

      fn square(&self) -> Self {
        Self(self.0.square())
      }
      fn double(&self) -> Self {
        *self + self
      }

      fn invert(&self) -> CtOption<Self> {
        let res = self.0.invert();
        CtOption::new(Self(res.0), res.1.into())
      }

      fn sqrt(&self) -> CtOption<Self> {
        // (p + 1) // 4, as valid since p % 4 == 3
        let mod_plus_one_div_four = $MODULUS.saturating_add(&U256::ONE).wrapping_div(&(4u8.into()));
        let res = self.pow(Self($ResidueType::new_checked(&mod_plus_one_div_four).unwrap()));
        CtOption::new(res, res.square().ct_eq(self))
      }

      fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        sqrt_ratio_generic(num, div)
      }
    }

    impl PrimeField for $FieldName {
      type Repr = [u8; 32];

      const MODULUS: &'static str = $MODULUS_STR;

      const NUM_BITS: u32 = $NUM_BITS;
      const CAPACITY: u32 = $NUM_BITS - 1;

      const TWO_INV: Self = $FieldName($ResidueType::new(&U256::from_u8(2)).invert().0);

      const MULTIPLICATIVE_GENERATOR: Self =
        Self(Residue::new(&U256::from_u8($MULTIPLICATIVE_GENERATOR)));
      const S: u32 = $S;

      const ROOT_OF_UNITY: Self = $FieldName(Residue::new(&U256::from_be_hex($ROOT_OF_UNITY)));
      const ROOT_OF_UNITY_INV: Self = Self(Self::ROOT_OF_UNITY.0.invert().0);

      const DELTA: Self = $FieldName(Residue::new(&U256::from_be_hex($DELTA)));

      fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
        let res = U256::from_le_slice(&bytes);
        CtOption::new($FieldName(Residue::new(&res)), res.ct_lt(&$MODULUS))
      }
      fn to_repr(&self) -> Self::Repr {
        let mut repr = [0; 32];
        repr.copy_from_slice(&self.0.retrieve().to_le_bytes());
        repr
      }

      fn is_odd(&self) -> Choice {
        self.0.retrieve().is_odd()
      }
    }

    impl PrimeFieldBits for $FieldName {
      type ReprBits = [u8; 32];

      fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
        self.to_repr().into()
      }

      fn char_le_bits() -> FieldBits<Self::ReprBits> {
        let mut repr = [0; 32];
        repr.copy_from_slice(&MODULUS.to_le_bytes());
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

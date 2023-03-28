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
        Self($inner::from(a))
      }
    }
  };
}

macro_rules! field {
  (
    $FieldName: ident,

    $MODULUS_STR: ident,
    $MODULUS: ident,
    $WIDE_MODULUS: ident,

    $NUM_BITS: literal,

    $TWO_INV: expr,
    $MULTIPLICATIVE_GENERATOR: literal,
    $ROOT_OF_UNITY_INV: expr,
    $DELTA: expr,
  ) => {
    use core::{
      ops::{DerefMut, Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign},
      iter::{Sum, Product},
    };

    use subtle::{Choice, CtOption, ConstantTimeEq, ConstantTimeLess, ConditionallySelectable};
    use rand_core::RngCore;

    use generic_array::{typenum::U57, GenericArray};
    use crypto_bigint::{Integer, NonZero, Encoding};

    use ff::{Field, PrimeField, FieldBits, PrimeFieldBits, helpers::sqrt_ratio_generic};

    use $crate::backend::u8_from_bool;

    fn reduce(x: U1024) -> U512 {
      U512::from_le_slice(&x.rem(&NonZero::new($WIDE_MODULUS).unwrap()).to_le_bytes()[.. 64])
    }

    impl ConstantTimeEq for $FieldName {
      fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
      }
    }

    impl ConditionallySelectable for $FieldName {
      fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        $FieldName(U512::conditional_select(&a.0, &b.0, choice))
      }
    }

    math_op!($FieldName, $FieldName, Add, add, AddAssign, add_assign, |x, y| U512::add_mod(
      &x,
      &y,
      &$MODULUS.0
    ));
    math_op!($FieldName, $FieldName, Sub, sub, SubAssign, sub_assign, |x, y| U512::sub_mod(
      &x,
      &y,
      &$MODULUS.0
    ));
    math_op!($FieldName, $FieldName, Mul, mul, MulAssign, mul_assign, |x, y| reduce(U1024::from(
      U512::mul_wide(&x, &y)
    )));

    from_wrapper!($FieldName, U512, u8);
    from_wrapper!($FieldName, U512, u16);
    from_wrapper!($FieldName, U512, u32);
    from_wrapper!($FieldName, U512, u64);
    from_wrapper!($FieldName, U512, u128);

    impl Neg for $FieldName {
      type Output = $FieldName;
      fn neg(self) -> $FieldName {
        Self(self.0.neg_mod(&$MODULUS.0))
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
        let mut table = [Self(U512::ONE); 16];
        table[1] = *self;
        for i in 2 .. 16 {
          table[i] = table[i - 1] * self;
        }

        let mut res = Self(U512::ONE);
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
            res *= table[usize::from(bits)];
            bits = 0;
          }
        }
        res
      }
    }

    impl Field for $FieldName {
      const ZERO: Self = Self(U512::ZERO);
      const ONE: Self = Self(U512::ONE);

      fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = [0; 128];
        rng.fill_bytes(&mut bytes);
        $FieldName(reduce(U1024::from_le_slice(bytes.as_ref())))
      }

      fn square(&self) -> Self {
        *self * self
      }
      fn double(&self) -> Self {
        $FieldName((self.0 << 1).rem(&NonZero::new($MODULUS.0).unwrap()))
      }

      fn invert(&self) -> CtOption<Self> {
        const NEG_2: $FieldName = Self($MODULUS.0.saturating_sub(&U512::from_u8(2)));
        CtOption::new(self.pow(NEG_2), !self.is_zero())
      }

      fn sqrt(&self) -> CtOption<Self> {
        const MOD_1_4: $FieldName =
          Self($MODULUS.0.saturating_add(&U512::from_u8(1)).wrapping_div(&U512::from_u8(4)));
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

      const TWO_INV: Self = $FieldName(U512::from_le_hex($TWO_INV));

      const MULTIPLICATIVE_GENERATOR: Self = Self(U512::from_u8($MULTIPLICATIVE_GENERATOR));
      // True for both the Ed448 Scalar field and FieldElement field
      const S: u32 = 1;

      // Both fields have their root of unity as -1
      const ROOT_OF_UNITY: Self = Self($MODULUS.0.saturating_sub(&U512::from_u8(1)));
      const ROOT_OF_UNITY_INV: Self = $FieldName(U512::from_le_hex($ROOT_OF_UNITY_INV));

      const DELTA: Self = $FieldName(U512::from_le_hex($DELTA));

      fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
        let res = $FieldName(U512::from_le_slice(&[bytes.as_ref(), [0; 7].as_ref()].concat()));
        CtOption::new(res, res.0.ct_lt(&$MODULUS.0))
      }
      fn to_repr(&self) -> Self::Repr {
        let mut repr = GenericArray::<u8, U57>::default();
        repr.copy_from_slice(&self.0.to_le_bytes()[.. 57]);
        repr
      }

      fn is_odd(&self) -> Choice {
        self.0.is_odd()
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
        MODULUS.to_le_bits()
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

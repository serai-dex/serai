pub(crate) mod scalar;
pub(crate) mod field;

#[doc(hidden)]
#[macro_export]
macro_rules! field {
  ($FieldName: ident, $MODULUS: ident, $MODULUS_INT: ident) => {
    use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign};

    use rand_core::RngCore;

    use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

    use generic_array::{typenum::U57, GenericArray};

    use num_traits::identities::{Zero, One};
    use num_bigint::RandBigInt;

    use $crate::{choice, math};

    pub(crate) fn from_repr_inner(bytes: GenericArray<u8, U57>) -> CtOption<BigUint> {
      let res = BigUint::from_bytes_le(bytes.as_ref());
      if bytes == $MODULUS.0 {
        return CtOption::new(res, 1.into());
      }
      CtOption::new(res.clone(), choice(res < *$MODULUS_INT))
    }

    pub(crate) fn to_repr_inner(element: BigUint) -> GenericArray<u8, U57> {
      let mut raw = element.to_bytes_le();
      while raw.len() < 57 {
        raw.push(0);
      }

      let mut repr = GenericArray::<u8, U57>::default();
      repr.copy_from_slice(&raw[.. 57]);
      repr
    }

    impl ConstantTimeEq for $FieldName {
      fn ct_eq(&self, other: &Self) -> Choice {
        choice(self.0 == other.0)
      }
    }

    impl ConditionallySelectable for $FieldName {
      fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        if choice.into() {
          *b
        } else {
          *a
        }
      }
    }

    math!(
      $FieldName,
      $FieldName,
      |x, y| to_repr_inner(
        &(from_repr_inner(x).unwrap() + from_repr_inner(y).unwrap()) % &*$MODULUS_INT
      ),
      |x, y| to_repr_inner(
        &((&from_repr_inner(x).unwrap() + &*$MODULUS_INT) - from_repr_inner(y).unwrap()) %
          &*$MODULUS_INT
      ),
      |x, y| to_repr_inner(
        &(from_repr_inner(x).unwrap() * from_repr_inner(y).unwrap()) % &*$MODULUS_INT
      )
    );

    impl From<u8> for $FieldName {
      fn from(x: u8) -> $FieldName {
        $FieldName(to_repr_inner(BigUint::from(x)))
      }
    }
    impl From<u16> for $FieldName {
      fn from(x: u16) -> $FieldName {
        $FieldName(to_repr_inner(BigUint::from(x)))
      }
    }
    impl From<u32> for $FieldName {
      fn from(x: u32) -> $FieldName {
        $FieldName(to_repr_inner(BigUint::from(x)))
      }
    }
    impl From<u64> for $FieldName {
      fn from(x: u64) -> $FieldName {
        $FieldName(to_repr_inner(BigUint::from(x)))
      }
    }

    lazy_static! {
      pub(crate) static ref ZERO: $FieldName = $FieldName(to_repr_inner(BigUint::zero()));
      pub(crate) static ref ONE: $FieldName = $FieldName(to_repr_inner(BigUint::one()));
      pub(crate) static ref TWO: $FieldName =
        $FieldName(to_repr_inner(BigUint::one() + BigUint::one()));
    }

    impl $FieldName {
      pub fn pow(&self, other: $FieldName) -> $FieldName {
        $FieldName(to_repr_inner(
          from_repr_inner(self.0)
            .unwrap()
            .modpow(&from_repr_inner(other.0).unwrap(), &$MODULUS_INT),
        ))
      }
    }

    pub(crate) fn random(mut rng: impl RngCore) -> $FieldName {
      let mut res = rng.gen_biguint(446);
      while res > *$MODULUS_INT {
        res = rng.gen_biguint(446);
      }
      $FieldName(to_repr_inner(res))
    }

    pub(crate) fn from_repr(bytes: GenericArray<u8, U57>) -> CtOption<$FieldName> {
      let opt = Option::from(from_repr_inner(bytes)).map(|x| $FieldName(to_repr_inner(x)));
      CtOption::new(opt.unwrap_or(*ZERO), choice(opt.is_some()))
    }

    pub(crate) fn to_repr(element: &$FieldName) -> GenericArray<u8, U57> {
      element.0
    }
  };
}

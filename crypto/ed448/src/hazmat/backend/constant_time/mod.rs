pub(crate) mod scalar;
pub(crate) mod field;

#[doc(hidden)]
#[macro_export]
macro_rules! field {
  ($FieldName: ident, $MODULUS: ident, $WIDE_MODULUS: ident) => {
    use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign};

    use rand_core::RngCore;

    use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

    use generic_array::{typenum::U57, GenericArray};
    use crypto_bigint::Encoding;

    use ff::PrimeFieldBits;

    use dalek_ff_group::{constant_time, from_uint};
    use $crate::{choice, math};

    fn reduce(x: U1024) -> U512 {
      U512::from_le_slice(&x.reduce(&$WIDE_MODULUS).unwrap().to_le_bytes()[.. 64])
    }

    constant_time!($FieldName, U512);
    math!(
      $FieldName,
      $FieldName,
      |x, y| U512::add_mod(&x, &y, &$MODULUS.0),
      |x, y| U512::sub_mod(&x, &y, &$MODULUS.0),
      |x, y| {
        let wide = U512::mul_wide(&x, &y);
        reduce(U1024::from((wide.1, wide.0)))
      }
    );
    from_uint!($FieldName, U512);

    lazy_static! {
      pub(crate) static ref ZERO: $FieldName = $FieldName(U512::ZERO);
      pub(crate) static ref ONE: $FieldName = $FieldName(U512::ONE);
      pub(crate) static ref TWO: $FieldName = $FieldName(U512::ONE.saturating_add(&U512::ONE));
    }

    impl $FieldName {
      pub fn pow(&self, other: $FieldName) -> $FieldName {
        let mut res = *ONE;
        let mut m = *self;
        for bit in other.to_le_bits() {
          res *= $FieldName::conditional_select(&ONE, &m, choice(bit));
          m *= m;
        }
        res
      }
    }

    pub(crate) fn random(mut rng: impl RngCore) -> $FieldName {
      let mut bytes = [0; 128];
      rng.fill_bytes(&mut bytes);
      $FieldName(reduce(U1024::from_le_slice(bytes.as_ref())))
    }

    pub(crate) fn from_repr(bytes: GenericArray<u8, U57>) -> CtOption<$FieldName> {
      let res = $FieldName(U512::from_le_slice(&[bytes.as_ref(), [0; 7].as_ref()].concat()));
      CtOption::new(res, res.0.add_mod(&U512::ZERO, &$MODULUS.0).ct_eq(&res.0))
    }

    pub(crate) fn to_repr(scalar: &$FieldName) -> GenericArray<u8, U57> {
      let mut repr = GenericArray::<u8, U57>::default();
      repr.copy_from_slice(&scalar.0.to_le_bytes()[.. 57]);
      repr
    }
  };
}

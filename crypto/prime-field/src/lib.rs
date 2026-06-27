#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

pub use subtle;
pub use zeroize;
pub use rand_core;
pub use ff;

#[doc(hidden)]
pub mod __prime_field_private {
  pub use crypto_bigint;
  pub use paste;
  #[cfg(feature = "std")]
  pub use ff_group_tests;

  use crypto_bigint::{Word, Uint, modular::ConstMontyParams};

  /// Remove the "0x"-prefix from a hex string.
  ///
  /// May panic if the string isn't valid hex.
  pub const fn hex_str_without_prefix(hex: &str) -> &str {
    if hex.len() < 2 {
      return hex;
    }

    if hex.as_bytes()[1] == b'x' {
      assert!(hex.as_bytes()[0] == b'0', "invalid hex string for modulus");
      hex.split_at(2).1
    } else {
      hex
    }
  }

  #[expect(clippy::as_conversions)]
  pub const fn uint_to_u64_words<const LIMBS: usize, const WORDS: usize>(
    value: Uint<LIMBS>,
  ) -> [u64; WORDS] {
    let mut res = [0u64; WORDS];
    let mut i = 0;
    while i < Uint::<LIMBS>::LIMBS {
      let word: Word = value.as_limbs()[i].0;
      const {
        assert!(Word::BITS <= u64::BITS);
      }
      let word = word as u64;
      let bits = i * (Word::BITS as usize);
      let j = bits / (u64::BITS as usize);
      res[j] |= (word << (bits % (u64::BITS as usize))) as u64;
      if (j + 1) < WORDS {
        if let Some(remaining_bits) =
          ((bits % (u64::BITS as usize)) + (Word::BITS as usize)).checked_sub(u64::BITS as usize)
        {
          if remaining_bits != 0 {
            res[j + 1] |= (word >> ((Word::BITS as usize) - remaining_bits)) as u64;
          }
        }
      }
      i += 1;
    }
    res
  }

  pub const fn u64_words_to_uint<const LIMBS: usize, const WORDS: usize>(
    words: [u64; WORDS],
  ) -> Uint<LIMBS> {
    let mut reconstruction = Uint::<LIMBS>::ZERO;
    let mut i = 0;
    #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
    while i < WORDS {
      const {
        assert!(Uint::<LIMBS>::BITS < u32::MAX);
      }
      reconstruction = reconstruction
        .bitor(&Uint::<LIMBS>::from_u64(words[i]).shl_vartime((i * (u64::BITS as usize)) as u32));
      i += 1;
    }
    reconstruction
  }

  #[expect(non_snake_case)]
  pub const fn calculate_S<const LIMBS: usize, P: ConstMontyParams<LIMBS>>() -> u32 {
    let mut i = 0;
    loop {
      let bit = P::PARAMS.modulus().as_ref().wrapping_sub(&Uint::<LIMBS>::ONE).bit_vartime(i);
      if !bit {
        i += 1;
        continue;
      }
      break;
    }
    i
  }
}

/// Construct a odd-prime field with a specified `Repr`.
///
/// The length of the `modulus_as_be_hex` string will effect the size of the underlying
/// representation and the encoding. It MAY have a "0x" prefix, if preferred.
///
/// `multiplicative_generator_as_be_hex` MAY have a "0x" prefix. It MAY be short and of a length
/// less than `modulus_as_be_hex`.
///
/// `big_endian` controls if the encoded representation will be big-endian or not.
///
/// `repr` must satisfy the requirements for `PrimeField::Repr`.
#[doc(hidden)]
#[macro_export]
macro_rules! odd_prime_field_with_specific_repr {
  (
    $name: ident,
    $modulus_as_be_hex: expr,
    $multiplicative_generator_as_be_hex: expr,
    $big_endian: literal,
    $repr: path
  ) => {
    prime_field::__prime_field_private::paste::paste! {
      mod [<$name __prime_field_private>] {
        use core::{
          ops::*,
          iter::{Sum, Product},
        };
        use prime_field::{
          subtle::{
            Choice, CtOption, ConstantTimeEq, ConditionallySelectable, ConditionallyNegatable,
          },
          zeroize::Zeroize,
          rand_core::RngCore,
          ff::*,
          __prime_field_private::{
            crypto_bigint::{
              ctutils::{self, CtEq as _, CtSelect as _, CtNeg as _},
              Limb, Encoding, Integer, Uint,
              modular::{ConstMontyParams, ConstMontyForm},
              const_monty_params,
            },
            *,
          },
        };

        const MODULUS_WITHOUT_PREFIX: &str = hex_str_without_prefix($modulus_as_be_hex);
        const MULTIPLICATIVE_GENERATOR_WITHOUT_PREFIX: &str =
          hex_str_without_prefix($multiplicative_generator_as_be_hex);

        const MODULUS_BYTES: usize = MODULUS_WITHOUT_PREFIX.len() / 2;
        /*
          `crypto-bigint` only implements some methods for some limbs, due to the lack of const
          generics. `next_power_of_two` pays a performance penalty yet effectively ensures this
          `Uint` type is fully defined.
        */
        type UnderlyingUint = Uint<{ MODULUS_BYTES.div_ceil(Limb::BYTES).next_power_of_two() }>;

        const PADDED_MODULUS_WITHOUT_PREFIX_BYTES: [u8; 2 * UnderlyingUint::BYTES] = {
          let mut res = [b'0'; 2 * UnderlyingUint::BYTES];
          let start = (2 * UnderlyingUint::BYTES) - MODULUS_WITHOUT_PREFIX.len();
          let mut i = start;
          while i < (2 * UnderlyingUint::BYTES) {
            res[i] = MODULUS_WITHOUT_PREFIX.as_bytes()[i - start];
            i += 1;
          }
          res
        };
        const PADDED_MODULUS_WITHOUT_PREFIX: &str = {
          match core::str::from_utf8(&PADDED_MODULUS_WITHOUT_PREFIX_BYTES) {
            Ok(res) => res,
            Err(_) => panic!("couldn't successfully pad modulus"),
          }
        };

        const PADDED_MULTIPLICATIVE_GENERATOR_WITHOUT_PREFIX_BYTES:
          [u8; 2 * UnderlyingUint::BYTES] = {
          let mut res = [b'0'; 2 * UnderlyingUint::BYTES];
          let start = (2 * UnderlyingUint::BYTES) - MULTIPLICATIVE_GENERATOR_WITHOUT_PREFIX.len();
          let mut i = start;
          while i < (2 * UnderlyingUint::BYTES) {
            res[i] = MULTIPLICATIVE_GENERATOR_WITHOUT_PREFIX.as_bytes()[i - start];
            i += 1;
          }
          res
        };
        const PADDED_MULTIPLICATIVE_GENERATOR_WITHOUT_PREFIX: &str = {
          match core::str::from_utf8(&PADDED_MULTIPLICATIVE_GENERATOR_WITHOUT_PREFIX_BYTES) {
            Ok(res) => res,
            Err(_) => panic!("couldn't successfully pad multiplicative generator"),
          }
        };

        const_monty_params!(Params, UnderlyingUint, PADDED_MODULUS_WITHOUT_PREFIX);
        type Underlying = ConstMontyForm<Params, { UnderlyingUint::LIMBS }>;

        const MODULUS: &UnderlyingUint = Params::PARAMS.modulus().as_ref();
        const MODULUS_MINUS_ONE: UnderlyingUint = MODULUS.wrapping_sub(&UnderlyingUint::ONE);
        const MODULUS_MINUS_TWO: UnderlyingUint = MODULUS.wrapping_sub(&UnderlyingUint::from_u8(2));
        const T: UnderlyingUint = MODULUS_MINUS_ONE.shr_vartime($name::S);

        /// A field automatically generated with `prime-field`.
        #[derive(Clone, Copy, Eq, Debug)]
        #[repr(transparent)]
        pub struct $name(Underlying);

        impl Default for $name {
          fn default() -> Self {
            Self::ZERO
          }
        }

        impl $name {
          /// Create a `$name` from the `Uint` type underlying it.
          #[expect(clippy::same_name_method)]
          const fn from(value: &UnderlyingUint) -> Self {
            $name(Underlying::new(value))
          }

          /// Create a `$name` from bytes within a `const` context.
          ///
          /// This function executes in variable time. `<$name as PrimeField>::from_repr` SHOULD
          /// be used instead.
          pub const fn from_bytes(value: &[u8; MODULUS_BYTES]) -> Option<Self> {
            let mut expanded_repr = [0; UnderlyingUint::BYTES];
            let repr: &[u8] = value.as_slice();
            let (uint, repr) = if $big_endian {
              let start = UnderlyingUint::BYTES - MODULUS_BYTES;
              let mut i = 0;
              while i < repr.len() {
                expanded_repr[start + i] = repr[i];
                i += 1;
              }
              let uint = Underlying::new(&UnderlyingUint::from_be_slice(&expanded_repr));
              (uint, uint.retrieve().to_be_bytes())
            } else {
              let mut i = 0;
              while i < repr.len() {
                expanded_repr[i] = repr[i];
                i += 1;
              }
              let uint = Underlying::new(&UnderlyingUint::from_le_slice(&expanded_repr));
              (uint, uint.retrieve().to_le_bytes())
            };

            // Ensure the representations match
            let mut i = 0;
            while i < expanded_repr.len() {
              if repr.as_slice()[i] != expanded_repr[i] {
                return None;
              }
              i += 1;
            }

            Some(Self(uint))
          }
        }
        impl From<u8> for $name {
          fn from(value: u8) -> Self {
            Self::from(&UnderlyingUint::from(value))
          }
        }
        impl From<u16> for $name {
          fn from(value: u16) -> Self {
            Self::from(&UnderlyingUint::from(value))
          }
        }
        impl From<u32> for $name {
          fn from(value: u32) -> Self {
            Self::from(&UnderlyingUint::from(value))
          }
        }
        impl From<u64> for $name {
          fn from(value: u64) -> Self {
            Self::from(&UnderlyingUint::from(value))
          }
        }

        impl ConstantTimeEq for $name {
          fn ct_eq(&self, other: &Self) -> Choice {
            self.0.ct_eq(&other.0).into()
          }
        }
        impl PartialEq for $name {
          fn eq(&self, other: &Self) -> bool {
            bool::from(self.ct_eq(other))
          }
        }

        impl ConditionallySelectable for $name {
          fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
            Self(<_>::ct_select(&a.0, &b.0, choice.into()))
          }
        }
        impl ConditionallyNegatable for $name {
          fn conditional_negate(&mut self, negate: Choice) {
            self.0 = <_>::ct_select(&self.0, &-self.0, negate.into());
          }
        }

        impl Zeroize for $name {
          fn zeroize(&mut self) {
            self.0.zeroize();
          }
        }

        impl Neg for $name {
          type Output = Self;
          fn neg(self) -> Self {
            Self(-self.0)
          }
        }

        impl Add for $name {
          type Output = Self;
          fn add(self, other: Self) -> Self {
            Self(self.0 + other.0)
          }
        }
        impl Sub for $name {
          type Output = Self;
          fn sub(self, other: Self) -> Self {
            Self(self.0 - other.0)
          }
        }
        impl Mul for $name {
          type Output = Self;
          fn mul(self, other: Self) -> Self {
            Self(self.0 * other.0)
          }
        }
        impl AddAssign for $name {
          fn add_assign(&mut self, other: Self) {
            self.0 += other.0;
          }
        }
        impl SubAssign for $name {
          fn sub_assign(&mut self, other: Self) {
            self.0 -= other.0;
          }
        }
        impl MulAssign for $name {
          fn mul_assign(&mut self, other: Self) {
            self.0 *= other.0;
          }
        }
        impl Sum for $name {
          fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
            let mut res = Self::ZERO;
            for item in iter {
              res += item;
            }
            res
          }
        }
        impl Product for $name {
          fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
            let mut res = Self::ONE;
            for item in iter {
              res *= item;
            }
            res
          }
        }
        impl<'a> Add<&'a Self> for $name {
          type Output = Self;
          fn add(self, other: &'a Self) -> Self {
            Self(self.0 + other.0)
          }
        }
        impl<'a> Sub<&'a Self> for $name {
          type Output = Self;
          fn sub(self, other: &'a Self) -> Self {
            Self(self.0 - other.0)
          }
        }
        impl<'a> Mul<&'a Self> for $name {
          type Output = Self;
          fn mul(self, other: &'a Self) -> Self {
            Self(self.0 * other.0)
          }
        }
        impl<'a> Sum<&'a Self> for $name {
          fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
            let mut res = Self::ZERO;
            for item in iter {
              res += item;
            }
            res
          }
        }
        impl<'a> Product<&'a Self> for $name {
          fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
            let mut res = Self::ONE;
            for item in iter {
              res *= item;
            }
            res
          }
        }
        impl<'a> AddAssign<&'a Self> for $name {
          fn add_assign(&mut self, other: &'a Self) {
            self.0 += other.0;
          }
        }
        impl<'a> SubAssign<&'a Self> for $name {
          fn sub_assign(&mut self, other: &'a Self) {
            self.0 -= other.0;
          }
        }
        impl<'a> MulAssign<&'a Self> for $name {
          fn mul_assign(&mut self, other: &'a Self) {
            self.0 *= other.0;
          }
        }

        impl Field for $name {
          const ZERO: Self = Self(Underlying::ZERO);
          const ONE: Self = Self(Underlying::ONE);
          fn random(mut rng: impl RngCore) -> Self {
            let mut bytes = [0; 2 * MODULUS_BYTES];
            rng.fill_bytes(&mut bytes);
            Self::from_uniform_bytes(&bytes)
          }
          fn square(&self) -> Self {
            Self(self.0.square())
          }
          fn double(&self) -> Self {
            Self(self.0.double())
          }
          fn invert(&self) -> CtOption<Self> {
            self.0.invert().map(Self).into()
          }
          fn sqrt(&self) -> CtOption<Self> {
            const THREE_MOD_FOUR: bool = (MODULUS.as_words()[0] % 4) == 3;
            const ONE_MOD_EIGHT: bool = (MODULUS.as_words()[0] % 8) == 1;
            const FIVE_MOD_EIGHT: bool = (MODULUS.as_words()[0] % 8) == 5;

            let mut sqrt = if THREE_MOD_FOUR {
              const SQRT_EXP: UnderlyingUint =
                MODULUS.shr_vartime(2).wrapping_add(&UnderlyingUint::ONE);
              Self(self.0.pow(&SQRT_EXP))
            } else if ONE_MOD_EIGHT {
              const TM1D2: UnderlyingUint = (T.wrapping_sub(&UnderlyingUint::ONE)).shr_vartime(1);
              #[expect(clippy::as_conversions)]
              const TM1D2_WORDS_LEN: usize = UnderlyingUint::BITS.div_ceil(u64::BITS) as usize;
              const TM1D2_WORDS: [u64; TM1D2_WORDS_LEN] = uint_to_u64_words(TM1D2);

              const TM1D2_RECONSTRUCTION: UnderlyingUint = u64_words_to_uint(TM1D2_WORDS);
              const RECONSTRUCTION_EQUALS_VALUE: bool = {
                let mut i = 0;
                let mut res = true;
                while i < TM1D2_WORDS_LEN {
                  res &= TM1D2_RECONSTRUCTION.as_words()[i] == TM1D2.as_words()[i];
                  i += 1;
                }
                res
              };
              #[expect(clippy::as_conversions)]
              const _ASSERT_RECONSTRUCTION_EQUALS_VALUE:
                [(); 0 - ((!RECONSTRUCTION_EQUALS_VALUE) as usize)] = [(); _];

              helpers::sqrt_tonelli_shanks::<Self, _>(self, TM1D2_WORDS).unwrap_or(Self::ZERO)
            } else {
              const SQRT_EXP: UnderlyingUint = MODULUS.shr_vartime(3);
              let upsilon = self.double().0.pow(&SQRT_EXP);
              let i = (upsilon.square() * &self.0).double();
              Self(upsilon * self.0 * (i - Self::ONE.0))
            };

            // Normalize to the even choice of square root
            // `let ()` is used to assert how `conditional_negate` operates in-place
            let () = sqrt.conditional_negate(sqrt.is_odd());

            CtOption::new(sqrt, sqrt.square().ct_eq(self).into())
          }
          fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
            helpers::sqrt_ratio_generic(num, div)
          }
        }

        /// The encoded representation of a `$name`.
        // This is required to be bespoke to satisfy `Default`.
        #[derive(Clone, Copy)]
        #[repr(transparent)]
        pub struct Repr([u8; MODULUS_BYTES]);
        impl Default for Repr {
          fn default() -> Self {
            Self([0; _])
          }
        }
        impl AsRef<[u8]> for Repr {
          fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
          }
        }
        impl AsMut<[u8]> for Repr {
          fn as_mut(&mut self) -> &mut [u8] {
            self.0.as_mut()
          }
        }

        impl PrimeField for $name {
          type Repr = $repr;
          const MODULUS: &str = $modulus_as_be_hex;
          const NUM_BITS: u32 = MODULUS.bits();
          const CAPACITY: u32 = Self::NUM_BITS - 1;
          const TWO_INV: Self =
            Self(Underlying::new(&UnderlyingUint::from_u8(2)).pow(&MODULUS_MINUS_TWO));
          const MULTIPLICATIVE_GENERATOR: Self = Self(
            Underlying::new(
              &UnderlyingUint::from_be_hex(PADDED_MULTIPLICATIVE_GENERATOR_WITHOUT_PREFIX)
            )
          );
          const S: u32 = calculate_S::<_, Params>();
          const ROOT_OF_UNITY: Self = Self(Self::MULTIPLICATIVE_GENERATOR.0.pow(&T));
          const ROOT_OF_UNITY_INV: Self = Self(Self::ROOT_OF_UNITY.0.pow(&MODULUS_MINUS_TWO));
          const DELTA: Self = {
            let two_to_the_s = UnderlyingUint::ONE.shl_vartime(Self::S);
            Self(Self::MULTIPLICATIVE_GENERATOR.0.pow(&two_to_the_s))
          };

          fn to_repr(&self) -> Self::Repr {
            let mut res = Self::Repr::default();
            {
              let res: &mut [u8] = res.as_mut();
              if $big_endian {
                let be_bytes = self.0.retrieve().to_be_bytes();
                res.copy_from_slice(
                  &be_bytes.as_slice()[(UnderlyingUint::BYTES - MODULUS_BYTES) ..]
                );
              } else {
                res.copy_from_slice(&self.0.retrieve().to_le_bytes().as_slice()[.. MODULUS_BYTES]);
              }
            }
            res
          }
          fn from_repr(repr: Self::Repr) -> CtOption<Self> {
            let mut expanded_repr = [0; UnderlyingUint::BYTES];
            let repr: &[u8] = repr.as_ref();
            let result = Self(if $big_endian {
              expanded_repr[(UnderlyingUint::BYTES - MODULUS_BYTES) .. ].copy_from_slice(repr);
              Underlying::new(&UnderlyingUint::from_be_bytes(expanded_repr.into()))
            } else {
              expanded_repr[.. MODULUS_BYTES].copy_from_slice(repr);
              Underlying::new(&UnderlyingUint::from_le_bytes(expanded_repr.into()))
            });
            CtOption::new(result, ctutils::CtEq::ct_eq(repr, &result.to_repr().as_ref()).into())
          }
          fn is_odd(&self) -> Choice {
            self.0.retrieve().is_odd().into()
          }
        }

        impl PrimeFieldBits for $name {
          type ReprBits = [u8; UnderlyingUint::BYTES];
          fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
            Self::ReprBits::from(self.0.retrieve().to_le_bytes()).into()
          }
          fn char_le_bits() -> FieldBits<Self::ReprBits> {
            Self::ReprBits::from(MODULUS.to_le_bytes()).into()
          }
        }

        impl FromUniformBytes<{ 2 * MODULUS_BYTES }> for $name {
          fn from_uniform_bytes(bytes: &[u8; 2 * MODULUS_BYTES]) -> Self {
            let mut expanded_wide_repr = [0; 2 * UnderlyingUint::BYTES];
            expanded_wide_repr[.. (2 * MODULUS_BYTES)].copy_from_slice(bytes);
            let bytes = expanded_wide_repr;

            let lo =
              Underlying::new(&UnderlyingUint::from_le_slice(&bytes[.. UnderlyingUint::BYTES]));
            let hi =
              Underlying::new(&UnderlyingUint::from_le_slice(&bytes[UnderlyingUint::BYTES ..]));
            const HI: Underlying = {
              let mut res = Underlying::new(&UnderlyingUint::ONE);
              let mut i = 0;
              while i < UnderlyingUint::BITS {
                res = res.double();
                i += 1;
              }
              res
            };
            Self(lo + (hi * HI))
          }
        }

        #[expect(clippy::as_conversions)]
        const BITS_PLUS_SECURITY_LEVEL: usize =
          (MODULUS.bits() + MODULUS.bits().div_ceil(2)) as usize;
        const BITS_PLUS_SECURITY_LEVEL_BYTES: usize = BITS_PLUS_SECURITY_LEVEL.div_ceil(8);
        impl FromUniformBytes<{ BITS_PLUS_SECURITY_LEVEL_BYTES }> for $name {
          fn from_uniform_bytes(bytes: &[u8; BITS_PLUS_SECURITY_LEVEL_BYTES]) -> Self {
            let mut larger = [0; 2 * MODULUS_BYTES];
            larger[.. BITS_PLUS_SECURITY_LEVEL_BYTES].copy_from_slice(bytes);
            Self::from_uniform_bytes(&larger)
          }
        }

        #[cfg(feature = "std")]
        #[test]
        fn test() {
          use prime_field::__prime_field_private::ff_group_tests;
          use ff_group_tests::prime_field::test_prime_field_bits;
          test_prime_field_bits::<_, $name>(&mut prime_field::rand_core::OsRng);
        }
      }

      pub use [<$name __prime_field_private>]::$name;
    }
  };
}

/// Construct a odd-prime field.
///
/// The length of the `modulus_as_be_hex` string will effect the size of the underlying
/// representation and the encoding. It MAY have a "0x" prefix, if preferred.
///
/// `multiplicative_generator_as_be_hex` MAY have a "0x" prefix. It MAY be short and of a length
/// less than `modulus_as_be_hex`. It MUST meet the requirements as stated in the documentation for
/// [`ff::PrimeField::MULTIPLICATIVE_GENERATOR`].
///
/// `big_endian` controls if the encoded representation will be big-endian or not.
#[macro_export]
macro_rules! odd_prime_field {
  (
    $name: ident,
    $modulus_as_be_hex: expr,
    $multiplicative_generator_as_be_hex: expr,
    $big_endian: literal
  ) => {
    prime_field::odd_prime_field_with_specific_repr!(
      $name,
      $modulus_as_be_hex,
      $multiplicative_generator_as_be_hex,
      $big_endian,
      Repr
    );
  };
}

use std_shims::prelude::*;

use rand_core::SeedableRng as _;
use rand_chacha::ChaCha20Rng;

use blake2::{
  digest::{
    array::{typenum::U32, Array},
    common::KeySizeUser,
    KeyInit, Mac as _,
  },
  Blake2sMac,
};
type Blake2s256Keyed = Blake2sMac<U32>;

use ciphersuite::{
  group::{
    ff::{PrimeField, FromUniformBytes},
    GroupEncoding as _,
  },
  WrappedGroup, Id, GroupIo,
};

use ec_divisors::DivisorCurve;
use generalized_bulletproofs::{GeneratorsError, Generators as BpGenerators};
use generalized_bulletproofs_ec_gadgets::*;

/// A pair of curves to perform the eVRF with.
pub trait Curves {
  /// The towering curve, for which the resulting key is on.
  type ToweringCurve: Id + GroupIo<F: FromUniformBytes<64>>;
  /// The embedded curve which participants represent their public keys over.
  type EmbeddedCurve: GroupIo<
    G: DivisorCurve<FieldElement = <Self::ToweringCurve as WrappedGroup>::F>,
  >;
  /// The parameters to use the embedded curve with the discrete-log gadget.
  type EmbeddedCurveParameters: DiscreteLogParameters;
}

/// Generators for an eVRF DKG.
///
/// These should be kept within a static. They're non-trivial to generate.
#[derive(Clone, Debug)]
pub struct Generators<C: Curves>(pub(crate) BpGenerators<C::ToweringCurve>);

impl<C: Curves> Generators<C> {
  /// Create a new set of generators.
  ///
  /// This is deterministic to the towering curve's (possibly truncated) ID and generator.
  pub fn new(max_threshold: u16, max_participants: u16) -> Generators<C> {
    let entropy = <Blake2s256Keyed as KeyInit>::new(&{
      let mut key = Array::<u8, <Blake2s256Keyed as KeySizeUser>::KeySize>::default();
      let key_len = key.len().min(<C::ToweringCurve as Id>::ID.len());
      {
        let key: &mut [u8] = key.as_mut();
        key[.. key_len].copy_from_slice(&<C::ToweringCurve as Id>::ID[.. key_len]);
      }
      key
    })
    .chain_update(<C::ToweringCurve as WrappedGroup>::generator().to_bytes())
    .finalize()
    .into_bytes();
    let mut rng = ChaCha20Rng::from_seed(entropy.into());

    /*
      This library outputs a key commited to over this generator, so it MUST be equal to the
      generator used by the Bulletproof to commit to values. This library also generally uses
      `generators.g()` interchangeably with `<C::ToweringCurve as WrappedGroup>::generator()` on
      assumption they're equivalent.
    */
    let g = <C::ToweringCurve as WrappedGroup>::generator();
    let h = crate::sample_point::<C::ToweringCurve>(&mut rng);

    #[expect(clippy::as_conversions)]
    const {
      assert!(
        (crate::Proof::<C>::generators_to_use(u16::MAX as usize, u16::MAX as usize) as u128) <
          (isize::MAX as u128)
      );
    }
    let generators_to_use =
      crate::Proof::<C>::generators_to_use(max_threshold.into(), max_participants.into());

    let mut g_bold = Vec::with_capacity(generators_to_use);
    let mut h_bold = Vec::with_capacity(generators_to_use);
    for _ in 0 .. generators_to_use {
      g_bold.push(crate::sample_point::<C::ToweringCurve>(&mut rng));
      h_bold.push(crate::sample_point::<C::ToweringCurve>(&mut rng));
    }

    match BpGenerators::new(g, h, g_bold, h_bold) {
      Ok(generators) => Self(generators),
      Err(GeneratorsError::GBoldEmpty | GeneratorsError::NotPowerOfTwo) => {
        unreachable!("`generators_to_use` didn't output a power of two")
      }
      Err(GeneratorsError::DifferingGhBoldLengths) => {
        unreachable!("`g_bold`, `h_bold` (pushed to at the same time) had different lengths?")
      }
      Err(GeneratorsError::IdentityPoint) => {
        unreachable!("`sample_point` sampled a non-identity point")
      }
      Err(GeneratorsError::DuplicatedGenerator) => {
        const SECURITY_PARAMETER: u32 = 128;
        const TARGETS: u32 = 64;
        const {
          /*
            Assert the odds of a collision across `2^{TARGETS}` is still negligible in the
            security parameter. This does assume `2^{TARGETS} > generators_to_use`, when its
            maximum value should be `~2^{20}`.
          */
          assert!(
            <<C::ToweringCurve as WrappedGroup>::F as PrimeField>::CAPACITY >=
              (SECURITY_PARAMETER + TARGETS)
          );
        }
        unreachable!(
          "uniform sampling on a curve of order `>= 2^{{{SECURITY_PARAMETER}}}` yielded a collision"
        );
      }
    }
  }
}

/// Ed25519, and an elliptic curve defined over its scalar field (embedwards25519).
#[cfg(test)]
#[derive(Debug, PartialEq)]
pub(crate) struct Ed25519;
#[cfg(test)]
impl Curves for Ed25519 {
  type ToweringCurve = dalek_ff_group::Ed25519;
  type EmbeddedCurve = embedwards25519::Embedwards25519;
  type EmbeddedCurveParameters = embedwards25519::Embedwards25519;
}

#[test]
fn generators() {
  use crate::Ed25519;
  assert!(crate::Proof::<Ed25519>::generators_to_use(0, 0).is_power_of_two());
  assert!(crate::Proof::<Ed25519>::generators_to_use(usize::from(u16::MAX), usize::from(u16::MAX))
    .is_power_of_two());
  assert!(
    crate::Proof::<Ed25519>::generators_to_use(usize::from(u16::MAX), usize::from(u16::MAX)) <=
      usize::try_from(u32::try_from(i32::MAX).unwrap()).unwrap()
  );
}

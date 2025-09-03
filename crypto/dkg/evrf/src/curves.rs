#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::vec::Vec;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use blake2::{
  digest::{
    array::{typenum::U32, Array},
    crypto_common::KeySizeUser,
    KeyInit, Mac,
  },
  Blake2sMac,
};
type Blake2s256Keyed = Blake2sMac<U32>;

use ciphersuite::{
  group::{ff::FromUniformBytes, GroupEncoding},
  WrappedGroup, Id, GroupIo,
};

use ec_divisors::DivisorCurve;
use generalized_bulletproofs::Generators as BpGenerators;
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
        key[.. key_len].copy_from_slice(&<C::ToweringCurve as Id>::ID[.. key_len])
      }
      key
    })
    .chain_update(<C::ToweringCurve as WrappedGroup>::generator().to_bytes())
    .finalize()
    .into_bytes();
    let mut rng = ChaCha20Rng::from_seed(entropy.into());

    let h = crate::sample_point::<C::ToweringCurve>(&mut rng);
    let generators =
      crate::Proof::<C>::generators_to_use(max_threshold.into(), max_participants.into());
    let mut g_bold = Vec::with_capacity(generators);
    let mut h_bold = Vec::with_capacity(generators);
    for _ in 0 .. generators {
      g_bold.push(crate::sample_point::<C::ToweringCurve>(&mut rng));
      h_bold.push(crate::sample_point::<C::ToweringCurve>(&mut rng));
    }
    Self(
      BpGenerators::new(<C::ToweringCurve as WrappedGroup>::generator(), h, g_bold, h_bold)
        .unwrap(),
    )
  }
}

/// Secp256k1, and an elliptic curve defined over its scalar field (secq256k1).
#[cfg(feature = "secp256k1")]
pub struct Secp256k1;
#[cfg(feature = "secp256k1")]
impl Curves for Secp256k1 {
  type ToweringCurve = ciphersuite_kp256::Secp256k1;
  type EmbeddedCurve = secq256k1::Secq256k1;
  type EmbeddedCurveParameters = secq256k1::Secq256k1;
}

/// Ed25519, and an elliptic curve defined over its scalar field (embedwards25519).
#[cfg(feature = "ed25519")]
pub struct Ed25519;
#[cfg(feature = "ed25519")]
impl Curves for Ed25519 {
  type ToweringCurve = dalek_ff_group::Ed25519;
  type EmbeddedCurve = embedwards25519::Embedwards25519;
  type EmbeddedCurveParameters = embedwards25519::Embedwards25519;
}

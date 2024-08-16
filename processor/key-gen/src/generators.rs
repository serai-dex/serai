use core::any::{TypeId, Any};
use std::{
  sync::{LazyLock, Mutex},
  collections::HashMap,
};

use dkg::evrf::*;

use serai_validator_sets_primitives::MAX_KEY_SHARES_PER_SET;

/// A cache of the generators used by the eVRF DKG.
///
/// This performs a lookup of the Ciphersuite to its generators. Since the Ciphersuite is a
/// generic, this takes advantage of `Any`. This static is isolated in a module to ensure
/// correctness can be evaluated solely by reviewing these few lines of code.
///
/// This is arguably over-engineered as of right now, as we only need generators for Ristretto
/// and N::Curve. By having this HashMap, we enable de-duplication of the Ristretto == N::Curve
/// case, and we automatically support the n-curve case (rather than hard-coding to the 2-curve
/// case).
static GENERATORS: LazyLock<Mutex<HashMap<TypeId, &'static (dyn Send + Sync + Any)>>> =
  LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn generators<C: EvrfCurve>() -> &'static EvrfGenerators<C> {
  GENERATORS
    .lock()
    .unwrap()
    .entry(TypeId::of::<C>())
    .or_insert_with(|| {
      // If we haven't prior needed generators for this Ciphersuite, generate new ones
      Box::leak(Box::new(EvrfGenerators::<C>::new(
        ((MAX_KEY_SHARES_PER_SET * 2 / 3) + 1).try_into().unwrap(),
        MAX_KEY_SHARES_PER_SET.try_into().unwrap(),
      )))
    })
    .downcast_ref()
    .unwrap()
}

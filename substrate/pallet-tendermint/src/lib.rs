#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::traits::OneSessionHandler;

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::*;

  #[pallet::config]
  pub trait Config: frame_system::Config {}

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);
}

pub use pallet::*;

pub mod crypto {
  use sp_application_crypto::{KeyTypeId, app_crypto, sr25519};
  app_crypto!(sr25519, KeyTypeId(*b"tend"));

  impl<C> sp_application_crypto::BoundToRuntimeAppPublic for crate::Pallet<C> {
    type Public = Public;
  }

  sp_application_crypto::with_pair! {
    pub type AuthorityPair = Pair;
  }
  pub type AuthoritySignature = Signature;
  pub type AuthorityId = Public;
}

impl<C, V> OneSessionHandler<V> for Pallet<C> {
  type Key = crypto::Public;

  fn on_genesis_session<'a, I: 'a>(_validators: I)
  where
    I: Iterator<Item = (&'a V, Self::Key)>,
    V: 'a,
  {
  }

  fn on_new_session<'a, I: 'a>(_changed: bool, _validators: I, _queued: I)
  where
    I: Iterator<Item = (&'a V, Self::Key)>,
    V: 'a,
  {
    /*
    if !changed {
      return;
    }

    for validator in validators {
      ...
    }
    */
  }

  fn on_disabled(_validator_index: u32) {}
}

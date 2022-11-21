#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use sp_std::vec::Vec;
  use sp_core::sr25519::Public;

  use frame_support::pallet_prelude::*;
  use frame_support::traits::{ConstU32, OneSessionHandler};

  type MaxValidators = ConstU32<{ u16::MAX as u32 }>;

  #[pallet::config]
  pub trait Config: frame_system::Config {}

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  #[pallet::getter(fn session)]
  pub type Session<T: Config> = StorageValue<_, u32, ValueQuery>;

  #[pallet::storage]
  #[pallet::getter(fn validators)]
  pub type Validators<T: Config> = StorageValue<_, BoundedVec<Public, MaxValidators>, ValueQuery>;

  pub mod crypto {
    use sp_application_crypto::{KeyTypeId, app_crypto, sr25519};
    app_crypto!(sr25519, KeyTypeId(*b"tend"));

    impl<T> sp_application_crypto::BoundToRuntimeAppPublic for crate::Pallet<T> {
      type Public = Public;
    }

    sp_application_crypto::with_pair! {
      pub type AuthorityPair = Pair;
    }
    pub type AuthoritySignature = Signature;
    pub type AuthorityId = Public;
  }

  impl<T: Config, V> OneSessionHandler<V> for Pallet<T> {
    type Key = crypto::Public;

    // TODO
    fn on_genesis_session<'a, I: 'a>(_validators: I)
    where
      I: Iterator<Item = (&'a V, Self::Key)>,
      V: 'a,
    {
    }

    fn on_new_session<'a, I: 'a>(changed: bool, validators: I, _queued: I)
    where
      I: Iterator<Item = (&'a V, Self::Key)>,
      V: 'a,
    {
      if !changed {
        return;
      }

      Session::<T>::put(Self::session() + 1);
      Validators::<T>::put(
        BoundedVec::try_from(validators.map(|(_, key)| key.into()).collect::<Vec<Public>>())
          .unwrap(),
      );
    }

    // TODO
    fn on_disabled(_validator_index: u32) {}
  }
}

pub use pallet::*;

#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::*;

  use validator_sets_primitives::{Amount, Coin, ValidatorSetIndex};

  #[derive(Default, Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, MaxEncodedLen)]
  #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
  pub struct ValidatorSet {
    bond: Amount,
    coins: BoundedVec<Coin, ConstU32<16>>,
  }

  #[pallet::config]
  pub trait Config: frame_system::Config {}

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  #[pallet::getter(fn validator_set)]
  pub type ValidatorSets<T: Config> =
    StorageMap<_, Blake2_128Concat, ValidatorSetIndex, ValidatorSet, ValueQuery>;

  #[pallet::storage]
  #[pallet::getter(fn key)]
  pub type Keys<T: Config> =
    StorageMap<_, Blake2_128Concat, (ValidatorSetIndex, Coin), ValidatorSet, ValueQuery>;

  /*
  #[pallet::storage]
  #[pallet::getter(fn validators)]
  pub type Validators<T: Config> = StorageValue<_, BoundedVec<Public, MaxValidators>, ValueQuery>;
  */

  // 1: Define validator sets
  // 2: Define coins
  // 3: Define keys

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    pub fn vote()
  }

  impl<T: Config, V> OneSessionHandler<V> for Pallet<T> {
    type Key = crypto::Public;

    fn on_genesis_session<'a, I: 'a>(_validators: I)
    where
      I: Iterator<Item = (&'a V, Self::Key)>,
      V: 'a,
    {
      ValidatorSets::<T>::put(
        0,
        ValidatorSet {
          bond: 1, // TODO
          coins: vec![BITCOIN, ETHEREUM, DAI, MONERO].try_into().unwrap(),
        }
      );
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

    fn on_disabled(_validator_index: u32) {}
  }
}

pub use pallet::*;

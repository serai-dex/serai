#![cfg_attr(not(feature = "std"), no_std)]

#[allow(clippy::cast_possible_truncation, clippy::no_effect_underscore_binding, clippy::empty_docs)]
#[frame_support::pallet]
pub mod pallet {
  use frame_system::pallet_prelude::*;
  use frame_support::{pallet_prelude::*, sp_runtime::SaturatedConversion};

  use dex_pallet::{Config as DexConfig, Pallet as Dex};
  use coins_pallet::{Config as CoinsConfig, AllowMint};

  use serai_primitives::*;

  #[pallet::config]
  pub trait Config: frame_system::Config + CoinsConfig + DexConfig {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    EconomicSecurityReached { network: NetworkId },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  #[pallet::getter(fn economic_security_block)]
  pub(crate) type EconomicSecurityBlock<T: Config> =
    StorageMap<_, Identity, NetworkId, BlockNumberFor<T>, OptionQuery>;

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(n: BlockNumberFor<T>) -> Weight {
      // we accept we reached economic security once we can mint smallest amount of a network's coin
      for coin in COINS {
        let existing = EconomicSecurityBlock::<T>::get(coin.network());
        if existing.is_none() &&
          Dex::<T>::security_oracle_value(coin).is_some() &&
          <T as CoinsConfig>::AllowMint::is_allowed(&Balance { coin, amount: Amount(1) })
        {
          EconomicSecurityBlock::<T>::set(coin.network(), Some(n));
          Self::deposit_event(Event::EconomicSecurityReached { network: coin.network() });
        }
      }

      Weight::zero() // TODO
    }
  }
}

pub use pallet::*;

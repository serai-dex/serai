#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

pub use tokens_primitives as primitives;

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;

  use serai_primitives::{Balance, SeraiAddress};
  use primitives::OutInstruction;

  use super::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<AccountId = SeraiAddress> {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    Mint { address: SeraiAddress, balance: Balance },
    Burn { address: SeraiAddress, balance: Balance, instruction: OutInstruction },
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(crate) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  fn burn<T: Config>(
    address: SeraiAddress,
    balance: Balance,
    instruction: OutInstruction,
  ) -> DispatchResult {
    Pallet::<T>::deposit_event(Event::Burn { address, balance, instruction });
    Ok(())
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn burn(
      origin: OriginFor<T>,
      balance: Balance,
      instruction: OutInstruction,
    ) -> DispatchResult {
      burn::<T>(ensure_signed(origin)?, balance, instruction)
    }
  }
}

pub use pallet::*;

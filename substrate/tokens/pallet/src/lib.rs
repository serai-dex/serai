#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

pub use tokens_primitives as primitives;

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::*;
  use frame_system::{pallet_prelude::*, RawOrigin};

  use pallet_assets::{Config as AssetsConfig, Pallet as AssetsPallet};

  use serai_primitives::{SubstrateAmount, Coin, Balance, PublicKey, SeraiAddress, AccountLookup};
  use primitives::{ADDRESS, OutInstruction};

  use super::*;

  #[pallet::config]
  pub trait Config:
    frame_system::Config<AccountId = PublicKey, Lookup = AccountLookup>
    + AssetsConfig<AssetIdParameter = Coin, AssetId = Coin, Balance = SubstrateAmount>
  {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    // Mint is technically redundant as the assets pallet has the exact same event already
    // Providing our own definition here just helps consolidate code
    Mint { address: SeraiAddress, balance: Balance },
    Burn { address: SeraiAddress, balance: Balance, instruction: OutInstruction },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  impl<T: Config> Pallet<T> {
    pub fn burn_internal(
      address: SeraiAddress,
      balance: Balance,
      instruction: OutInstruction,
    ) -> DispatchResult {
      AssetsPallet::<T>::burn(
        RawOrigin::Signed(ADDRESS.into()).into(),
        balance.coin,
        address,
        balance.amount.0,
      )?;
      Pallet::<T>::deposit_event(Event::Burn { address, balance, instruction });
      Ok(())
    }

    pub fn mint(address: SeraiAddress, balance: Balance) {
      // TODO: Prevent minting when it'd cause an amount exceeding the bond
      AssetsPallet::<T>::mint(
        RawOrigin::Signed(ADDRESS.into()).into(),
        balance.coin,
        address,
        balance.amount.0,
      )
      .unwrap();
      Pallet::<T>::deposit_event(Event::Mint { address, balance });
    }

    pub fn balance(coin: Coin, address: SeraiAddress) -> SubstrateAmount {
      AssetsPallet::<T>::balance(coin, PublicKey::from(address))
    }

    pub fn transfer(
      origin: OriginFor<T>,
      coin: Coin,
      target: SeraiAddress,
      amount: SubstrateAmount,
    ) -> DispatchResult {
      AssetsPallet::<T>::transfer(origin, coin, target, amount)
    }
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
      Self::burn_internal(ensure_signed(origin)?.into(), balance, instruction)
    }
  }
}

pub use pallet::*;

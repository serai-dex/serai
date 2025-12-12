#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[expect(
  let_underscore_drop,
  clippy::as_conversions,
  clippy::cast_possible_truncation,
  clippy::semicolon_if_nothing_returned
)]
#[frame_support::pallet]
mod pallet {
  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use serai_abi::{
    primitives::{prelude::*, crypto::Signature, genesis_liquidity::GenesisValues},
    genesis_liquidity::Event,
  };

  use serai_core_pallet::Pallet as Core;

  use super::*;

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::CoinsInstance>
    + serai_coins_pallet::Config<serai_coins_pallet::LiquidityTokensInstance>
    + serai_dex_pallet::Config
  {
  }

  /// An error incurred.
  #[pallet::error]
  pub enum Error<T> {}

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> Pallet<T> {
    #[expect(unused)]
    fn emit_event(event: Event) {
      Core::<T>::emit_event(event)
    }
  }

  impl<T: Config> Pallet<T> {
    /// Add liquidity on behalf of the specified address.
    pub fn add_liquidity(to: SeraiAddress, balance: ExternalBalance) -> Result<(), Error<T>> {
      todo!("TODO {to:?} {balance:?}")
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Oraclize the values of the coins available on genesis, relative to BTC.
    ///
    /// This will trigger the addition of the liquidity into the pools and their initialization.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn oraclize_values(
      origin: OriginFor<T>,
      values: GenesisValues,
      signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;
      todo!("TODO {values:?} {signature:?}")
    }

    /// Transfer genesis liquidity.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn transfer_genesis_liquidity(
      origin: OriginFor<T>,
      to: SeraiAddress,
      genesis_liquidity: ExternalBalance,
    ) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      todo!("TODO {signer:?} {to:?} {genesis_liquidity:?}")
    }

    /// Remove genesis liquidity.
    #[pallet::call_index(2)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn remove_genesis_liquidity(
      origin: OriginFor<T>,
      genesis_liquidity: ExternalBalance,
    ) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      todo!("TODO {signer:?} {genesis_liquidity:?}")
    }
  }
}

pub use pallet::*;

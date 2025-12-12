#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[expect(
  let_underscore_drop,
  clippy::cast_possible_truncation,
  clippy::semicolon_if_nothing_returned
)]
#[frame_support::pallet]
mod pallet {
  use serai_abi::{primitives::prelude::*, economic_security::Event};

  use serai_core_pallet::Pallet as Core;

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

  // TODO
  impl<T: Config> serai_abi::economic_security::EconomicSecurity for Pallet<T> {
    fn achieved_economic_security(_network: ExternalNetworkId) -> bool {
      false
    }
    fn sri_value(_balance: ExternalBalance) -> Amount {
      Amount(0)
    }
  }
}

pub use pallet::*;

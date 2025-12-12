#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[expect(let_underscore_drop, clippy::cast_possible_truncation)]
#[frame_support::pallet]
mod pallet {
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
}

pub use pallet::*;

#[frame_support::pallet]
mod core_pallet {
  use ::alloc::*;
  use frame_support::pallet_prelude::*;

  #[pallet::storage]
  pub type NextNonce<T: Config> =
    StorageMap<_, Blake2_128Concat, T::AccountId, T::Nonce, ValueQuery>;
  #[pallet::storage]
  pub type Blocks<T: Config> = StorageMap<_, Identity, T::Hash, (), OptionQuery>;

  #[pallet::config]
  pub trait Config: frame_system::Config {}

  #[pallet::pallet]
  pub struct Pallet<T>(_);
}
pub(super) use core_pallet::*;

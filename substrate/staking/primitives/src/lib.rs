#![cfg_attr(not(feature = "std"), no_std)]

use frame_system::pallet::Config;

pub trait AllocatedStaking<T: Config> {
  type Error;

  // TODO: Should this specify the allocator, handling tracking that as well?
  // Or should each allocator have a map of AccountId -> u64 on their end?
  fn allocate(account: &T::AccountId, amount: u64) -> Result<(), Self::Error>;
  fn deallocate(account: &T::AccountId, amount: u64) -> Result<(), Self::Error>;
}

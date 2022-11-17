#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::vec::Vec;

pub type Amount = u64;
pub type Curve = u16;
pub type Coin = u32;
pub type GlobalValidatorSetIndex = u32;
pub type ValidatorSetIndex = u16;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ValidatorSet {
  bond: Amount,
  coins: Vec<Coin>,
}

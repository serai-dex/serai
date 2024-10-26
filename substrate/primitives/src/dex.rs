#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};

use crate::{Coin, SubstrateAmount};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, MaxEncodedLen)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QuotePriceParams {
  pub coin1: Coin,
  pub coin2: Coin,
  pub amount: SubstrateAmount,
  pub include_fee: bool,
  pub exact_in: bool,
}

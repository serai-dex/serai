use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

/// The type used to identify coins.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Coin(pub u32);
impl From<u32> for Coin {
  fn from(coin: u32) -> Coin {
    Coin(coin)
  }
}

pub const SERAI: Coin = Coin(0);
pub const BITCOIN: Coin = Coin(1);
pub const ETHER: Coin = Coin(2);
pub const DAI: Coin = Coin(3);
pub const MONERO: Coin = Coin(4);

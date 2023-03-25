#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use sp_core::{ConstU32, bounded::BoundedVec};

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

/// The type used to identify networks.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct NetworkId(pub u16);
impl From<u16> for NetworkId {
  fn from(network: u16) -> NetworkId {
    NetworkId(network)
  }
}

pub const BITCOIN_NET_ID: NetworkId = NetworkId(0);
pub const ETHEREUM_NET_ID: NetworkId = NetworkId(1);
pub const MONERO_NET_ID: NetworkId = NetworkId(2);

/// The type used to identify coins.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
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

// Max of 8 coins per network
// Since Serai isn't interested in listing tokens, as on-chain DEXs will almost certainly have
// more liquidity, the only reason we'd have so many coins from a network is if there's no DEX
// on-chain
// There's probably no chain with so many *worthwhile* coins and no on-chain DEX
// This could probably be just 4, yet 8 is a hedge for the unforseen
// If necessary, this can be increased with a fork
pub const MAX_COINS_PER_NETWORK: u32 = 8;

/// Network definition.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Network {
  coins: BoundedVec<Coin, ConstU32<{ MAX_COINS_PER_NETWORK }>>,
}

#[cfg(feature = "std")]
impl Zeroize for Network {
  fn zeroize(&mut self) {
    for coin in self.coins.as_mut() {
      coin.zeroize();
    }
    self.coins.truncate(0);
  }
}

impl Network {
  #[cfg(feature = "std")]
  pub fn new(coins: Vec<Coin>) -> Result<Network, &'static str> {
    Ok(Network {
      coins: coins.try_into().map_err(|_| "coins length exceeds {MAX_COINS_PER_NETWORK}")?,
    })
  }

  pub fn coins(&self) -> &[Coin] {
    &self.coins
  }
}

#[cfg(feature = "std")]
lazy_static::lazy_static! {
  pub static ref BITCOIN_NET: Network = Network::new(vec![BITCOIN]).unwrap();
  pub static ref ETHEREUM_NET: Network = Network::new(vec![ETHER, DAI]).unwrap();
  pub static ref MONERO_NET: Network = Network::new(vec![MONERO]).unwrap();
}

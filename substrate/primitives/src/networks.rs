#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(feature = "std")]
use zeroize::Zeroize;

use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use sp_core::{ConstU32, bounded::BoundedVec};

/// The type used to identify networks.
#[derive(
  Clone,
  Copy,
  PartialEq,
  Eq,
  Hash,
  Debug,
  Serialize,
  Deserialize,
  Encode,
  Decode,
  MaxEncodedLen,
  TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub enum NetworkId {
  Serai,
  Bitcoin,
  Ethereum,
  Monero,
}

/// The type used to identify coins.
#[derive(
  Clone,
  Copy,
  PartialEq,
  Eq,
  Hash,
  Debug,
  Serialize,
  Deserialize,
  Encode,
  Decode,
  MaxEncodedLen,
  TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub enum Coin {
  Serai,
  Bitcoin,
  Ether,
  Dai,
  Monero,
}

impl Coin {
  pub fn network(&self) -> NetworkId {
    match self {
      Coin::Serai => NetworkId::Serai,
      Coin::Bitcoin => NetworkId::Bitcoin,
      Coin::Ether => NetworkId::Ethereum,
      Coin::Dai => NetworkId::Ethereum,
      Coin::Monero => NetworkId::Monero,
    }
  }
}

// Max of 8 coins per network
// Since Serai isn't interested in listing tokens, as on-chain DEXs will almost certainly have
// more liquidity, the only reason we'd have so many coins from a network is if there's no DEX
// on-chain
// There's probably no chain with so many *worthwhile* coins and no on-chain DEX
// This could probably be just 4, yet 8 is a hedge for the unforseen
// If necessary, this can be increased with a fork
pub const MAX_COINS_PER_NETWORK: u32 = 8;

/// Network definition.
#[derive(
  Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
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
    if coins.is_empty() {
      Err("no coins provided")?;
    }

    let network = coins[0].network();
    for coin in coins.iter().skip(1) {
      if coin.network() != network {
        Err("coins have different networks")?;
      }
    }

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
  pub static ref NETWORKS: HashMap<NetworkId, Network> = HashMap::from([
    (NetworkId::Serai, Network::new(vec![Coin::Serai]).unwrap()),
    (NetworkId::Bitcoin, Network::new(vec![Coin::Bitcoin]).unwrap()),
    (NetworkId::Ethereum, Network::new(vec![Coin::Ether, Coin::Dai]).unwrap()),
    (NetworkId::Monero, Network::new(vec![Coin::Monero]).unwrap()),
  ]);
}

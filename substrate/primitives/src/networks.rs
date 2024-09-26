#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use sp_core::{ConstU32, bounded::BoundedVec};
use sp_std::{vec, vec::Vec};

#[cfg(feature = "borsh")]
use crate::{borsh_serialize_bounded_vec, borsh_deserialize_bounded_vec};

/// The type used to identify external networks.
#[derive(
  Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, PartialOrd, Ord, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExternalNetworkId {
  Bitcoin,
  Ethereum,
  Monero,
}

/// The type used to identify networks.
#[derive(
  Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, PartialOrd, Ord, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkId {
  Serai,
  External(ExternalNetworkId),
}

impl ExternalNetworkId {
  pub fn coins(&self) -> Vec<ExternalCoin> {
    match self {
      Self::Bitcoin => vec![ExternalCoin::Bitcoin],
      Self::Ethereum => vec![ExternalCoin::Ether, ExternalCoin::Dai],
      Self::Monero => vec![ExternalCoin::Monero],
    }
  }
}

impl NetworkId {
  pub fn coins(&self) -> Vec<Coin> {
    match self {
      Self::Serai => vec![Coin::Serai],
      Self::External(network) => {
        network.coins().into_iter().map(core::convert::Into::into).collect()
      }
    }
  }
}

impl From<ExternalNetworkId> for NetworkId {
  fn from(network: ExternalNetworkId) -> Self {
    match network {
      ExternalNetworkId::Bitcoin => Self::External(ExternalNetworkId::Bitcoin),
      ExternalNetworkId::Ethereum => Self::External(ExternalNetworkId::Ethereum),
      ExternalNetworkId::Monero => Self::External(ExternalNetworkId::Monero),
    }
  }
}

impl TryFrom<NetworkId> for ExternalNetworkId {
  type Error = ();

  fn try_from(network: NetworkId) -> Result<Self, Self::Error> {
    match network {
      NetworkId::Serai => Err(())?,
      NetworkId::External(n) => Ok(n),
    }
  }
}

pub const EXTERNAL_NETWORKS: [ExternalNetworkId; 3] =
  [ExternalNetworkId::Bitcoin, ExternalNetworkId::Ethereum, ExternalNetworkId::Monero];

pub const NETWORKS: [NetworkId; 4] = [
  NetworkId::Serai,
  NetworkId::External(ExternalNetworkId::Bitcoin),
  NetworkId::External(ExternalNetworkId::Ethereum),
  NetworkId::External(ExternalNetworkId::Monero),
];

pub const EXTERNAL_COINS: [ExternalCoin; 4] =
  [ExternalCoin::Bitcoin, ExternalCoin::Ether, ExternalCoin::Dai, ExternalCoin::Monero];

pub const COINS: [Coin; 5] = [
  Coin::Serai,
  Coin::External(ExternalCoin::Bitcoin),
  Coin::External(ExternalCoin::Ether),
  Coin::External(ExternalCoin::Dai),
  Coin::External(ExternalCoin::Monero),
];

/// The type used to identify coins.
#[derive(
  Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Coin {
  Serai,
  External(ExternalCoin),
}

/// The type used to identify external coins.
#[derive(
  Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExternalCoin {
  Bitcoin,
  Ether,
  Dai,
  Monero,
}

impl From<ExternalCoin> for Coin {
  fn from(coin: ExternalCoin) -> Self {
    match coin {
      ExternalCoin::Bitcoin => Self::External(ExternalCoin::Bitcoin),
      ExternalCoin::Ether => Self::External(ExternalCoin::Ether),
      ExternalCoin::Dai => Self::External(ExternalCoin::Dai),
      ExternalCoin::Monero => Self::External(ExternalCoin::Monero),
    }
  }
}

impl TryFrom<Coin> for ExternalCoin {
  type Error = ();

  fn try_from(coin: Coin) -> Result<Self, Self::Error> {
    match coin {
      Coin::Serai => Err(())?,
      Coin::External(c) => Ok(c),
    }
  }
}

impl ExternalCoin {
  pub fn network(&self) -> ExternalNetworkId {
    match self {
      ExternalCoin::Bitcoin => ExternalNetworkId::Bitcoin,
      ExternalCoin::Ether | ExternalCoin::Dai => ExternalNetworkId::Ethereum,
      ExternalCoin::Monero => ExternalNetworkId::Monero,
    }
  }

  pub fn name(&self) -> &'static str {
    match self {
      ExternalCoin::Bitcoin => "Bitcoin",
      ExternalCoin::Ether => "Ether",
      ExternalCoin::Dai => "Dai Stablecoin",
      ExternalCoin::Monero => "Monero",
    }
  }

  pub fn symbol(&self) -> &'static str {
    match self {
      ExternalCoin::Bitcoin => "BTC",
      ExternalCoin::Ether => "ETH",
      ExternalCoin::Dai => "DAI",
      ExternalCoin::Monero => "XMR",
    }
  }

  pub fn decimals(&self) -> u32 {
    match self {
      // Ether and DAI have 18 decimals, yet we only track 8 in order to fit them within u64s
      ExternalCoin::Bitcoin | ExternalCoin::Ether | ExternalCoin::Dai => 8,
      ExternalCoin::Monero => 12,
    }
  }
}

impl Coin {
  pub fn native() -> Coin {
    Coin::Serai
  }

  pub fn network(&self) -> NetworkId {
    match self {
      Coin::Serai => NetworkId::Serai,
      Coin::External(c) => c.network().into(),
    }
  }

  pub fn name(&self) -> &'static str {
    match self {
      Coin::Serai => "Serai",
      Coin::External(c) => c.name(),
    }
  }

  pub fn symbol(&self) -> &'static str {
    match self {
      Coin::Serai => "SRI",
      Coin::External(c) => c.symbol(),
    }
  }

  pub fn decimals(&self) -> u32 {
    match self {
      // Ether and DAI have 18 decimals, yet we only track 8 in order to fit them within u64s
      Coin::Serai => 8,
      Coin::External(c) => c.decimals(),
    }
  }

  pub fn is_native(&self) -> bool {
    matches!(self, Coin::Serai)
  }
}

// Max of 8 coins per network
// Since Serai isn't interested in listing tokens, as on-chain DEXs will almost certainly have
// more liquidity, the only reason we'd have so many coins from a network is if there's no DEX
// on-chain
// There's probably no chain with so many *worthwhile* coins and no on-chain DEX
// This could probably be just 4, yet 8 is a hedge for the unforeseen
// If necessary, this can be increased with a fork
pub const MAX_COINS_PER_NETWORK: u32 = 8;

/// Network definition.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Network {
  #[cfg_attr(
    feature = "borsh",
    borsh(
      serialize_with = "borsh_serialize_bounded_vec",
      deserialize_with = "borsh_deserialize_bounded_vec"
    )
  )]
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

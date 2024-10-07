#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Decode, Encode, EncodeLike, MaxEncodedLen};
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
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExternalNetworkId {
  Bitcoin,
  Ethereum,
  Monero,
}

impl Encode for ExternalNetworkId {
  fn encode(&self) -> Vec<u8> {
    match self {
      ExternalNetworkId::Bitcoin => vec![1],
      ExternalNetworkId::Ethereum => vec![2],
      ExternalNetworkId::Monero => vec![3],
    }
  }
}

impl Decode for ExternalNetworkId {
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    let kind = input.read_byte()?;
    match kind {
      1 => Ok(Self::Bitcoin),
      2 => Ok(Self::Ethereum),
      3 => Ok(Self::Monero),
      _ => Err(scale::Error::from("invalid format")),
    }
  }
}

impl MaxEncodedLen for ExternalNetworkId {
  fn max_encoded_len() -> usize {
    1
  }
}

impl EncodeLike for ExternalNetworkId {}

#[cfg(feature = "borsh")]
impl BorshSerialize for ExternalNetworkId {
  fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
    writer.write_all(&self.encode())
  }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for ExternalNetworkId {
  fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
    let mut kind = [0; 1];
    reader.read_exact(&mut kind)?;
    ExternalNetworkId::decode(&mut kind.as_slice())
      .map_err(|_| std::io::Error::other("invalid format"))
  }
}

/// The type used to identify networks.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkId {
  Serai,
  External(ExternalNetworkId),
}

impl Encode for NetworkId {
  fn encode(&self) -> Vec<u8> {
    match self {
      NetworkId::Serai => vec![0],
      NetworkId::External(network) => network.encode(),
    }
  }
}

impl Decode for NetworkId {
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    let kind = input.read_byte()?;
    match kind {
      0 => Ok(Self::Serai),
      _ => Ok(ExternalNetworkId::decode(&mut [kind].as_slice())?.into()),
    }
  }
}

impl MaxEncodedLen for NetworkId {
  fn max_encoded_len() -> usize {
    1
  }
}

impl EncodeLike for NetworkId {}

#[cfg(feature = "borsh")]
impl BorshSerialize for NetworkId {
  fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
    writer.write_all(&self.encode())
  }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for NetworkId {
  fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
    let mut kind = [0; 1];
    reader.read_exact(&mut kind)?;
    NetworkId::decode(&mut kind.as_slice()).map_err(|_| std::io::Error::other("invalid format"))
  }
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
    NetworkId::External(network)
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

/// The type used to identify external coins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExternalCoin {
  Bitcoin,
  Ether,
  Dai,
  Monero,
}

impl Encode for ExternalCoin {
  fn encode(&self) -> Vec<u8> {
    match self {
      ExternalCoin::Bitcoin => vec![4],
      ExternalCoin::Ether => vec![5],
      ExternalCoin::Dai => vec![6],
      ExternalCoin::Monero => vec![7],
    }
  }
}

impl Decode for ExternalCoin {
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    let kind = input.read_byte()?;
    match kind {
      4 => Ok(Self::Bitcoin),
      5 => Ok(Self::Ether),
      6 => Ok(Self::Dai),
      7 => Ok(Self::Monero),
      _ => Err(scale::Error::from("invalid format")),
    }
  }
}
impl MaxEncodedLen for ExternalCoin {
  fn max_encoded_len() -> usize {
    1
  }
}

impl EncodeLike for ExternalCoin {}

#[cfg(feature = "borsh")]
impl BorshSerialize for ExternalCoin {
  fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
    writer.write_all(&self.encode())
  }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for ExternalCoin {
  fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
    let mut kind = [0; 1];
    reader.read_exact(&mut kind)?;
    ExternalCoin::decode(&mut kind.as_slice()).map_err(|_| std::io::Error::other("invalid format"))
  }
}

/// The type used to identify coins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Coin {
  Serai,
  External(ExternalCoin),
}

impl Encode for Coin {
  fn encode(&self) -> Vec<u8> {
    match self {
      Coin::Serai => vec![0],
      Coin::External(ec) => ec.encode(),
    }
  }
}

impl Decode for Coin {
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    let kind = input.read_byte()?;
    match kind {
      0 => Ok(Self::Serai),
      _ => Ok(ExternalCoin::decode(&mut [kind].as_slice())?.into()),
    }
  }
}

impl MaxEncodedLen for Coin {
  fn max_encoded_len() -> usize {
    1
  }
}

impl EncodeLike for Coin {}

#[cfg(feature = "borsh")]
impl BorshSerialize for Coin {
  fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
    writer.write_all(&self.encode())
  }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for Coin {
  fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
    let mut kind = [0; 1];
    reader.read_exact(&mut kind)?;
    Coin::decode(&mut kind.as_slice()).map_err(|_| std::io::Error::other("invalid format"))
  }
}

impl From<ExternalCoin> for Coin {
  fn from(coin: ExternalCoin) -> Self {
    Coin::External(coin)
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

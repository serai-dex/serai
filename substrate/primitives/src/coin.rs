use zeroize::Zeroize;

use borsh::{io, BorshSerialize, BorshDeserialize};

use crate::network_id::{ExternalNetworkId, NetworkId};

/// The type used to identify coins native to external networks.
///
/// This type serializes to a subset of `Coin`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen, scale::DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(sp_core::serde::Serialize, sp_core::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "sp_core::serde"))]
#[non_exhaustive]
pub enum ExternalCoin {
  /// Bitcoin, from the Bitcoin network.
  Bitcoin = 1,
  /// Ether, from the Ethereum network.
  Ether = 2,
  /// Dai Stablecoin, from the Ethereum network.
  Dai = 3,
  /// Monero, from the Monero network.
  Monero = 4,
}

impl ExternalCoin {
  /// All external coins.
  pub fn all() -> impl Iterator<Item = Self> {
    [ExternalCoin::Bitcoin, ExternalCoin::Ether, ExternalCoin::Dai, ExternalCoin::Monero]
      .into_iter()
  }
}

/// The type used to identify coins.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen, scale::DecodeWithMemTracking)
)]
#[cfg_attr(feature = "non_canonical_scale_derivations", allow(clippy::cast_possible_truncation))]
#[cfg_attr(feature = "serde", derive(sp_core::serde::Serialize, sp_core::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "sp_core::serde"))]
pub enum Coin {
  /// The Serai coin.
  Serai,
  /// An external coin.
  External(ExternalCoin),
}

impl BorshSerialize for Coin {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Self::Serai => writer.write_all(&[0]),
      Self::External(external) => external.serialize(writer),
    }
  }
}

impl BorshDeserialize for Coin {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;
    match kind[0] {
      0 => Ok(Self::Serai),
      _ => ExternalCoin::deserialize_reader(&mut kind.as_slice()).map(Into::into),
    }
  }
}

impl Coin {
  /// All coins.
  pub fn all() -> impl Iterator<Item = Self> {
    core::iter::once(Coin::Serai).chain(ExternalCoin::all().map(Into::into))
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
      Coin::External(ext) => Ok(ext),
    }
  }
}

impl ExternalCoin {
  /// The external network this coin is native to.
  pub fn network(&self) -> ExternalNetworkId {
    match self {
      ExternalCoin::Bitcoin => ExternalNetworkId::Bitcoin,
      ExternalCoin::Ether | ExternalCoin::Dai => ExternalNetworkId::Ethereum,
      ExternalCoin::Monero => ExternalNetworkId::Monero,
    }
  }

  /// The decimals used for a single human unit of this coin.
  ///
  /// This may be less than the decimals used for a single human unit of this coin *by defined
  /// convention*. If so, that means Serai is *truncating* the decimals. A coin which is defined
  /// as having 8 decimals, while Serai claims it has 4 decimals, will have `0.00019999`
  /// interpreted as `0.0001` (in human units, in atomic units, 19999 will be interpreted as 1).
  pub fn decimals(&self) -> u32 {
    match self {
      // Ether and DAI have 18 decimals, yet we only track 8 in order to fit them within u64s
      ExternalCoin::Bitcoin | ExternalCoin::Ether | ExternalCoin::Dai => 8,
      ExternalCoin::Monero => 12,
    }
  }
}

impl Coin {
  /// The network this coin is native to.
  pub fn network(&self) -> NetworkId {
    match self {
      Coin::Serai => NetworkId::Serai,
      Coin::External(c) => c.network().into(),
    }
  }

  /// The decimals used for a single human unit of this coin.
  ///
  /// This may be less than the decimals used for a single human unit of this coin *by defined
  /// convention*. If so, that means Serai is *truncating* the decimals. A coin which is defined
  /// as having 8 decimals, while Serai claims it has 4 decimals, will have `0.00019999`
  /// interpreted as `0.0001` (in human units, in atomic units, 19999 will be interpreted as 1).
  pub fn decimals(&self) -> u32 {
    match self {
      Coin::Serai => 9,
      Coin::External(c) => c.decimals(),
    }
  }
}

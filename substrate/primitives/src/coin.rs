use zeroize::Zeroize;

use borsh::{io, BorshSerialize, BorshDeserialize};

use crate::network_id::{ExternalNetworkId, NetworkId};

/// The type used to identify coins native to external networks.
///
/// This type serializes to a subset of `Coin`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
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
#[cfg(feature = "scale")]
crate::borsh_as_scale!(ExternalCoin);
#[cfg(feature = "scale")]
impl scale::MaxEncodedLen for ExternalCoin {
  fn max_encoded_len() -> usize {
    1
  }
}
#[cfg(feature = "scale")]
impl scale::EncodeLike<Coin> for ExternalCoin {}

impl ExternalCoin {
  /// All external coins.
  pub fn all() -> impl Iterator<Item = Self> {
    [ExternalCoin::Bitcoin, ExternalCoin::Ether, ExternalCoin::Dai, ExternalCoin::Monero]
      .into_iter()
  }
}

/// The type used to identify coins.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
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

#[cfg(feature = "scale")]
crate::borsh_as_scale!(Coin);
#[cfg(feature = "scale")]
impl scale::MaxEncodedLen for Coin {
  fn max_encoded_len() -> usize {
    1
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
  pub const fn network(&self) -> ExternalNetworkId {
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
  pub const fn decimals(&self) -> u32 {
    match self {
      // Ether and DAI have 18 decimals, yet we only track 8 in order to fit them within `u64`s
      ExternalCoin::Bitcoin | ExternalCoin::Ether | ExternalCoin::Dai => 8,
      ExternalCoin::Monero => 12,
    }
  }
}

impl Coin {
  /// The network this coin is native to.
  pub const fn network(&self) -> NetworkId {
    match self {
      Coin::Serai => NetworkId::Serai,
      Coin::External(c) => NetworkId::External(c.network()),
    }
  }

  /// The decimals used for a single human unit of this coin.
  ///
  /// This may be less than the decimals used for a single human unit of this coin *by defined
  /// convention*. If so, that means Serai is *truncating* the decimals. A coin which is defined
  /// as having 8 decimals, while Serai claims it has 4 decimals, will have `0.00019999`
  /// interpreted as `0.0001` (in human units, in atomic units, 19999 will be interpreted as 1).
  pub const fn decimals(&self) -> u32 {
    match self {
      Coin::Serai => 9,
      Coin::External(c) => c.decimals(),
    }
  }
}

#[test]
fn external_coin() {
  for coin in ExternalCoin::all() {
    assert_eq!(ExternalCoin::try_from(Coin::External(coin)).unwrap(), coin);
    assert_eq!(NetworkId::from(coin.network()), Coin::External(coin).network());
    assert_eq!(coin.decimals(), Coin::External(coin).decimals());

    assert_eq!(
      ExternalCoin::deserialize_reader(&mut borsh::to_vec(&coin).unwrap().as_slice()).unwrap(),
      coin
    );
    assert_eq!(borsh::to_vec(&Coin::External(coin)).unwrap(), borsh::to_vec(&coin).unwrap());

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};
      assert_eq!(coin.encode(), borsh::to_vec(&coin).unwrap());
      assert!(coin.encode().len() <= Coin::max_encoded_len());
      assert_eq!(ExternalCoin::decode_all(&mut coin.encode().as_slice()).unwrap(), coin);
      assert_eq!(Coin::External(coin).encode(), coin.encode());
    }
  }
}

#[test]
fn coin() {
  use std::collections::HashSet;

  ExternalCoin::try_from(Coin::Serai).unwrap_err();

  for coin in Coin::all() {
    assert_eq!(
      Coin::deserialize_reader(&mut borsh::to_vec(&coin).unwrap().as_slice()).unwrap(),
      coin
    );

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};
      assert_eq!(coin.encode(), borsh::to_vec(&coin).unwrap());
      assert!(coin.encode().len() <= Coin::max_encoded_len());
      assert_eq!(Coin::decode_all(&mut coin.encode().as_slice()).unwrap(), coin);
    }
  }

  {
    let mut all_coins = Coin::all().collect::<HashSet<_>>();
    assert!(all_coins.remove(&Coin::Serai));
    assert_eq!(all_coins, ExternalCoin::all().map(Coin::from).collect::<HashSet<_>>());
  }
}

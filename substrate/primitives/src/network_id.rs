use zeroize::Zeroize;

use borsh::{io, BorshSerialize, BorshDeserialize};

use crate::coin::{ExternalCoin, Coin};

/// Identifier for an embedded elliptic curve.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Zeroize)]
#[derive(BorshSerialize, BorshDeserialize)]
pub enum EmbeddedEllipticCurve {
  /// The Embedwards25519 curve, defined over (embedded into) Ed25519's/Ristretto's scalar field.
  Embedwards25519,
  /// The secq256k1 curve, forming a cycle with secp256k1.
  Secq256k1,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(EmbeddedEllipticCurve);

/// The type used to identify external networks.
///
/// This type serializes to a subset of `NetworkId`.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Zeroize)]
#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
pub enum ExternalNetworkId {
  /// The Bitcoin network.
  Bitcoin = 1,
  /// The Ethereum network.
  Ethereum = 2,
  /// The Monero network.
  Monero = 3,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(ExternalNetworkId);
#[cfg(feature = "scale")]
impl scale::MaxEncodedLen for ExternalNetworkId {
  fn max_encoded_len() -> usize {
    1
  }
}

#[expect(clippy::as_conversions)]
impl From<ExternalNetworkId> for u8 {
  fn from(network_id: ExternalNetworkId) -> Self {
    network_id as u8
  }
}

impl ExternalNetworkId {
  /// All external networks.
  pub fn all() -> impl Iterator<Item = Self> {
    [ExternalNetworkId::Bitcoin, ExternalNetworkId::Ethereum, ExternalNetworkId::Monero].into_iter()
  }
}

impl ExternalNetworkId {
  /// The embedded elliptic curves actively used for this network.
  ///
  /// This is guaranteed to return `[Embedwards25519]` or
  /// `[Embedwards25519, *network specific curve*]`.
  pub fn embedded_elliptic_curves(&self) -> impl Iterator<Item = EmbeddedEllipticCurve> {
    match self {
      // We need to generate a Ristretto key for oraclizing and a Secp256k1 key for the network
      Self::Bitcoin | Self::Ethereum => {
        [EmbeddedEllipticCurve::Embedwards25519, EmbeddedEllipticCurve::Secq256k1]
          .as_slice()
          .iter()
          .copied()
      }
      // Since the oraclizing key curve is the same as the network's curve, we only need it
      Self::Monero => [EmbeddedEllipticCurve::Embedwards25519].as_slice().iter().copied(),
    }
  }

  /// The coins native to this network.
  pub fn coins(&self) -> impl Iterator<Item = ExternalCoin> {
    match self {
      Self::Bitcoin => [ExternalCoin::Bitcoin].as_slice().iter().copied(),
      Self::Ethereum => [ExternalCoin::Ether, ExternalCoin::Dai].as_slice().iter().copied(),
      Self::Monero => [ExternalCoin::Monero].as_slice().iter().copied(),
    }
  }
}

/// The type used to identify networks.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Zeroize)]
pub enum NetworkId {
  /// The Serai network.
  Serai,
  /// An external network.
  External(ExternalNetworkId),
}

impl BorshSerialize for NetworkId {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Self::Serai => writer.write_all(&[0]),
      Self::External(external) => external.serialize(writer),
    }
  }
}

impl BorshDeserialize for NetworkId {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;
    match kind[0] {
      0 => Ok(Self::Serai),
      _ => ExternalNetworkId::deserialize_reader(&mut kind.as_slice()).map(Into::into),
    }
  }
}

#[cfg(feature = "scale")]
crate::borsh_as_scale!(NetworkId);
#[cfg(feature = "scale")]
impl scale::MaxEncodedLen for NetworkId {
  fn max_encoded_len() -> usize {
    1
  }
}

impl NetworkId {
  /// All networks.
  pub fn all() -> impl Iterator<Item = Self> {
    core::iter::once(NetworkId::Serai).chain(ExternalNetworkId::all().map(Into::into))
  }

  /// The coins native to this network.
  pub fn coins(self) -> impl Iterator<Item = Coin> {
    let (coins, external_coins): (&[Coin], _) = match self {
      NetworkId::Serai => (&[Coin::Serai], None),
      NetworkId::External(ext) => (&[], Some(ext.coins())),
    };
    coins.iter().copied().chain(external_coins.into_iter().flatten().map(Into::into))
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
      NetworkId::External(ext) => Ok(ext),
    }
  }
}

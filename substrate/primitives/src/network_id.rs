use zeroize::Zeroize;

use borsh::{io, BorshSerialize, BorshDeserialize};

use crate::coin::{ExternalCoin, Coin};

/// Identifier for an embedded elliptic curve.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub enum EmbeddedEllipticCurve {
  /// The Embedwards25519 curve, defined over (embedded into) Ed25519's/Ristretto's scalar field.
  Embedwards25519,
  /// The secq256k1 curve, forming a cycle with secp256k1.
  Secq256k1,
}

/// The type used to identify external networks.
///
/// This type serializes to a subset of `NetworkId`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen)
)]
#[non_exhaustive]
pub enum ExternalNetworkId {
  /// The Bitcoin network.
  Bitcoin = 1,
  /// The Ethereum network.
  Ethereum = 2,
  /// The Monero network.
  Monero = 3,
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
  pub fn embedded_elliptic_curves(&self) -> &'static [EmbeddedEllipticCurve] {
    match self {
      // We need to generate a Ristretto key for oraclizing and a Secp256k1 key for the network
      Self::Bitcoin | Self::Ethereum => {
        &[EmbeddedEllipticCurve::Embedwards25519, EmbeddedEllipticCurve::Secq256k1]
      }
      // Since the oraclizing key curve is the same as the network's curve, we only need it
      Self::Monero => &[EmbeddedEllipticCurve::Embedwards25519],
    }
  }

  /// The coins native to this network.
  pub fn coins(&self) -> &'static [ExternalCoin] {
    match self {
      Self::Bitcoin => &[ExternalCoin::Bitcoin],
      Self::Ethereum => &[ExternalCoin::Ether, ExternalCoin::Dai],
      Self::Monero => &[ExternalCoin::Monero],
    }
  }
}

/// The type used to identify networks.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen)
)]
#[cfg_attr(feature = "non_canonical_scale_derivations", allow(clippy::cast_possible_truncation))]
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

impl NetworkId {
  /// All networks.
  pub fn all() -> impl Iterator<Item = Self> {
    core::iter::once(NetworkId::Serai).chain(ExternalNetworkId::all().map(Into::into))
  }

  /// The coins native to this network.
  pub fn coins(self) -> impl Iterator<Item = Coin> {
    let (coins, external_coins): (&[Coin], &[ExternalCoin]) = match self {
      NetworkId::Serai => (&[Coin::Serai], &[]),
      NetworkId::External(ext) => (&[], ext.coins()),
    };
    coins.iter().copied().chain(external_coins.iter().copied().map(Into::into))
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

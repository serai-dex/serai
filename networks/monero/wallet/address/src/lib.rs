#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::{self, Write};
use std_shims::{
  vec,
  string::{String, ToString},
};

use zeroize::Zeroize;

use curve25519_dalek::EdwardsPoint;

use monero_io::*;

mod base58check;
use base58check::{encode_check, decode_check};

#[cfg(test)]
mod tests;

/// The address type.
///
/// The officially specified addresses are supported, along with
/// [Featured Addresses](https://gist.github.com/kayabaNerve/01c50bbc35441e0bbdcee63a9d823789).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum AddressType {
  /// A legacy address type.
  Legacy,
  /// A legacy address with a payment ID embedded.
  LegacyIntegrated([u8; 8]),
  /// A subaddress.
  ///
  /// This is what SHOULD be used if specific functionality isn't needed.
  Subaddress,
  /// A featured address.
  ///
  /// Featured Addresses are an unofficial address specification which is meant to be extensible
  /// and support a variety of functionality. This functionality includes being a subaddresses AND
  /// having a payment ID, along with being immune to the burning bug.
  ///
  /// At this time, support for featured addresses is limited to this crate. There should be no
  /// expectation of interoperability.
  Featured {
    /// If this address is a subaddress.
    subaddress: bool,
    /// The payment ID associated with this address.
    payment_id: Option<[u8; 8]>,
    /// If this address is guaranteed.
    ///
    /// A guaranteed address is one where any outputs scanned to it are guaranteed to be spendable
    /// under the hardness of various cryptographic problems (which are assumed hard). This is via
    /// a modified shared-key derivation which eliminates the burning bug.
    guaranteed: bool,
  },
}

impl AddressType {
  /// If this address is a subaddress.
  pub fn is_subaddress(&self) -> bool {
    matches!(self, AddressType::Subaddress) ||
      matches!(self, AddressType::Featured { subaddress: true, .. })
  }

  /// The payment ID within this address.
  pub fn payment_id(&self) -> Option<[u8; 8]> {
    if let AddressType::LegacyIntegrated(id) = self {
      Some(*id)
    } else if let AddressType::Featured { payment_id, .. } = self {
      *payment_id
    } else {
      None
    }
  }

  /// If this address is guaranteed.
  ///
  /// A guaranteed address is one where any outputs scanned to it are guaranteed to be spendable
  /// under the hardness of various cryptographic problems (which are assumed hard). This is via
  /// a modified shared-key derivation which eliminates the burning bug.
  pub fn is_guaranteed(&self) -> bool {
    matches!(self, AddressType::Featured { guaranteed: true, .. })
  }
}

/// A subaddress index.
///
/// Subaddresses are derived from a root using a `(account, address)` tuple as an index.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct SubaddressIndex {
  account: u32,
  address: u32,
}

impl SubaddressIndex {
  /// Create a new SubaddressIndex.
  pub const fn new(account: u32, address: u32) -> Option<SubaddressIndex> {
    if (account == 0) && (address == 0) {
      return None;
    }
    Some(SubaddressIndex { account, address })
  }

  /// Get the account this subaddress index is under.
  pub const fn account(&self) -> u32 {
    self.account
  }

  /// Get the address this subaddress index is for, within its account.
  pub const fn address(&self) -> u32 {
    self.address
  }
}

/// Bytes used as prefixes when encoding addresses.
///
/// These distinguish the address's type.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct AddressBytes {
  legacy: u8,
  legacy_integrated: u8,
  subaddress: u8,
  featured: u8,
}

impl AddressBytes {
  /// Create a new set of address bytes, one for each address type.
  pub const fn new(
    legacy: u8,
    legacy_integrated: u8,
    subaddress: u8,
    featured: u8,
  ) -> Option<Self> {
    if (legacy == legacy_integrated) || (legacy == subaddress) || (legacy == featured) {
      return None;
    }
    if (legacy_integrated == subaddress) || (legacy_integrated == featured) {
      return None;
    }
    if subaddress == featured {
      return None;
    }
    Some(AddressBytes { legacy, legacy_integrated, subaddress, featured })
  }

  const fn to_const_generic(self) -> u32 {
    ((self.legacy as u32) << 24) +
      ((self.legacy_integrated as u32) << 16) +
      ((self.subaddress as u32) << 8) +
      (self.featured as u32)
  }

  #[allow(clippy::cast_possible_truncation)]
  const fn from_const_generic(const_generic: u32) -> Self {
    let legacy = (const_generic >> 24) as u8;
    let legacy_integrated = ((const_generic >> 16) & (u8::MAX as u32)) as u8;
    let subaddress = ((const_generic >> 8) & (u8::MAX as u32)) as u8;
    let featured = (const_generic & (u8::MAX as u32)) as u8;

    AddressBytes { legacy, legacy_integrated, subaddress, featured }
  }
}

// https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
//   /src/cryptonote_config.h#L216-L225
// https://gist.github.com/kayabaNerve/01c50bbc35441e0bbdcee63a9d823789 for featured
const MONERO_MAINNET_BYTES: AddressBytes = match AddressBytes::new(18, 19, 42, 70) {
  Some(bytes) => bytes,
  None => panic!("mainnet byte constants conflicted"),
};
// https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
//   /src/cryptonote_config.h#L277-L281
const MONERO_STAGENET_BYTES: AddressBytes = match AddressBytes::new(24, 25, 36, 86) {
  Some(bytes) => bytes,
  None => panic!("stagenet byte constants conflicted"),
};
// https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
//   /src/cryptonote_config.h#L262-L266
const MONERO_TESTNET_BYTES: AddressBytes = match AddressBytes::new(53, 54, 63, 111) {
  Some(bytes) => bytes,
  None => panic!("testnet byte constants conflicted"),
};

/// The network this address is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum Network {
  /// A mainnet address.
  Mainnet,
  /// A stagenet address.
  ///
  /// Stagenet maintains parity with mainnet and is useful for testing integrations accordingly.
  Stagenet,
  /// A testnet address.
  ///
  /// Testnet is used to test new consensus rules and functionality.
  Testnet,
}

/// Errors when decoding an address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum AddressError {
  /// The address had an invalid (network, type) byte.
  #[cfg_attr(feature = "std", error("invalid byte for the address's network/type ({0})"))]
  InvalidTypeByte(u8),
  /// The address wasn't a valid Base58Check (as defined by Monero) string.
  #[cfg_attr(feature = "std", error("invalid address encoding"))]
  InvalidEncoding,
  /// The data encoded wasn't the proper length.
  #[cfg_attr(feature = "std", error("invalid length"))]
  InvalidLength,
  /// The address had an invalid key.
  #[cfg_attr(feature = "std", error("invalid key"))]
  InvalidKey,
  /// The address was featured with unrecognized features.
  #[cfg_attr(feature = "std", error("unknown features"))]
  UnknownFeatures(u64),
  /// The network was for a different network than expected.
  #[cfg_attr(
    feature = "std",
    error("different network ({actual:?}) than expected ({expected:?})")
  )]
  DifferentNetwork {
    /// The Network expected.
    expected: Network,
    /// The Network embedded within the Address.
    actual: Network,
  },
}

/// Bytes used as prefixes when encoding addresses, variable to the network instance.
///
/// These distinguish the address's network and type.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct NetworkedAddressBytes {
  mainnet: AddressBytes,
  stagenet: AddressBytes,
  testnet: AddressBytes,
}

impl NetworkedAddressBytes {
  /// Create a new set of address bytes, one for each network.
  pub const fn new(
    mainnet: AddressBytes,
    stagenet: AddressBytes,
    testnet: AddressBytes,
  ) -> Option<Self> {
    let res = NetworkedAddressBytes { mainnet, stagenet, testnet };
    let all_bytes = res.to_const_generic();

    let mut i = 0;
    while i < 12 {
      let this_byte = (all_bytes >> (32 + (i * 8))) & (u8::MAX as u128);

      let mut j = 0;
      while j < 12 {
        if i == j {
          j += 1;
          continue;
        }
        let other_byte = (all_bytes >> (32 + (j * 8))) & (u8::MAX as u128);
        if this_byte == other_byte {
          return None;
        }

        j += 1;
      }

      i += 1;
    }

    Some(res)
  }

  /// Convert this set of address bytes to its representation as a u128.
  ///
  /// We cannot use this struct directly as a const generic unfortunately.
  pub const fn to_const_generic(self) -> u128 {
    ((self.mainnet.to_const_generic() as u128) << 96) +
      ((self.stagenet.to_const_generic() as u128) << 64) +
      ((self.testnet.to_const_generic() as u128) << 32)
  }

  #[allow(clippy::cast_possible_truncation)]
  const fn from_const_generic(const_generic: u128) -> Self {
    let mainnet = AddressBytes::from_const_generic((const_generic >> 96) as u32);
    let stagenet =
      AddressBytes::from_const_generic(((const_generic >> 64) & (u32::MAX as u128)) as u32);
    let testnet =
      AddressBytes::from_const_generic(((const_generic >> 32) & (u32::MAX as u128)) as u32);

    NetworkedAddressBytes { mainnet, stagenet, testnet }
  }

  fn network(&self, network: Network) -> &AddressBytes {
    match network {
      Network::Mainnet => &self.mainnet,
      Network::Stagenet => &self.stagenet,
      Network::Testnet => &self.testnet,
    }
  }

  fn byte(&self, network: Network, kind: AddressType) -> u8 {
    let address_bytes = self.network(network);

    match kind {
      AddressType::Legacy => address_bytes.legacy,
      AddressType::LegacyIntegrated(_) => address_bytes.legacy_integrated,
      AddressType::Subaddress => address_bytes.subaddress,
      AddressType::Featured { .. } => address_bytes.featured,
    }
  }

  // This will return an incomplete AddressType for LegacyIntegrated/Featured.
  fn metadata_from_byte(&self, byte: u8) -> Result<(Network, AddressType), AddressError> {
    let mut meta = None;
    for network in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
      let address_bytes = self.network(network);
      if let Some(kind) = match byte {
        _ if byte == address_bytes.legacy => Some(AddressType::Legacy),
        _ if byte == address_bytes.legacy_integrated => Some(AddressType::LegacyIntegrated([0; 8])),
        _ if byte == address_bytes.subaddress => Some(AddressType::Subaddress),
        _ if byte == address_bytes.featured => {
          Some(AddressType::Featured { subaddress: false, payment_id: None, guaranteed: false })
        }
        _ => None,
      } {
        meta = Some((network, kind));
        break;
      }
    }

    meta.ok_or(AddressError::InvalidTypeByte(byte))
  }
}

/// The bytes used for distinguishing Monero addresses.
pub const MONERO_BYTES: NetworkedAddressBytes = match NetworkedAddressBytes::new(
  MONERO_MAINNET_BYTES,
  MONERO_STAGENET_BYTES,
  MONERO_TESTNET_BYTES,
) {
  Some(bytes) => bytes,
  None => panic!("Monero network byte constants conflicted"),
};

/// A Monero address.
#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Address<const ADDRESS_BYTES: u128> {
  network: Network,
  kind: AddressType,
  spend: EdwardsPoint,
  view: EdwardsPoint,
}

impl<const ADDRESS_BYTES: u128> fmt::Debug for Address<ADDRESS_BYTES> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
    let hex = |bytes: &[u8]| -> String {
      let mut res = String::with_capacity(2 + (2 * bytes.len()));
      res.push_str("0x");
      for b in bytes {
        write!(&mut res, "{b:02x}").unwrap();
      }
      res
    };

    fmt
      .debug_struct("Address")
      .field("network", &self.network)
      .field("kind", &self.kind)
      .field("spend", &hex(&self.spend.compress().to_bytes()))
      .field("view", &hex(&self.view.compress().to_bytes()))
      // This is not a real field yet is the most valuable thing to know when debugging
      .field("(address)", &self.to_string())
      .finish()
  }
}

impl<const ADDRESS_BYTES: u128> fmt::Display for Address<ADDRESS_BYTES> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let address_bytes: NetworkedAddressBytes =
      NetworkedAddressBytes::from_const_generic(ADDRESS_BYTES);

    let mut data = vec![address_bytes.byte(self.network, self.kind)];
    data.extend(self.spend.compress().to_bytes());
    data.extend(self.view.compress().to_bytes());
    if let AddressType::Featured { subaddress, payment_id, guaranteed } = self.kind {
      let features_uint =
        (u8::from(guaranteed) << 2) + (u8::from(payment_id.is_some()) << 1) + u8::from(subaddress);
      write_varint(&features_uint, &mut data).unwrap();
    }
    if let Some(id) = self.kind.payment_id() {
      data.extend(id);
    }
    write!(f, "{}", encode_check(data))
  }
}

impl<const ADDRESS_BYTES: u128> Address<ADDRESS_BYTES> {
  /// Create a new address.
  pub fn new(network: Network, kind: AddressType, spend: EdwardsPoint, view: EdwardsPoint) -> Self {
    Address { network, kind, spend, view }
  }

  /// Parse an address from a String, accepting any network it is.
  pub fn from_str_with_unchecked_network(s: &str) -> Result<Self, AddressError> {
    let raw = decode_check(s).ok_or(AddressError::InvalidEncoding)?;
    let mut raw = raw.as_slice();

    let address_bytes: NetworkedAddressBytes =
      NetworkedAddressBytes::from_const_generic(ADDRESS_BYTES);
    let (network, mut kind) = address_bytes
      .metadata_from_byte(read_byte(&mut raw).map_err(|_| AddressError::InvalidLength)?)?;
    let spend = read_point(&mut raw).map_err(|_| AddressError::InvalidKey)?;
    let view = read_point(&mut raw).map_err(|_| AddressError::InvalidKey)?;

    if matches!(kind, AddressType::Featured { .. }) {
      let features = read_varint::<_, u64>(&mut raw).map_err(|_| AddressError::InvalidLength)?;
      if (features >> 3) != 0 {
        Err(AddressError::UnknownFeatures(features))?;
      }

      let subaddress = (features & 1) == 1;
      let integrated = ((features >> 1) & 1) == 1;
      let guaranteed = ((features >> 2) & 1) == 1;

      kind =
        AddressType::Featured { subaddress, payment_id: integrated.then_some([0; 8]), guaranteed };
    }

    // Read the payment ID, if there should be one
    match kind {
      AddressType::LegacyIntegrated(ref mut id) |
      AddressType::Featured { payment_id: Some(ref mut id), .. } => {
        *id = read_bytes(&mut raw).map_err(|_| AddressError::InvalidLength)?;
      }
      _ => {}
    };

    if !raw.is_empty() {
      Err(AddressError::InvalidLength)?;
    }

    Ok(Address { network, kind, spend, view })
  }

  /// Create a new address from a `&str`.
  ///
  /// This takes in an argument for the expected network, erroring if a distinct network was used.
  /// It also errors if the address is invalid (as expected).
  pub fn from_str(network: Network, s: &str) -> Result<Self, AddressError> {
    Self::from_str_with_unchecked_network(s).and_then(|addr| {
      if addr.network == network {
        Ok(addr)
      } else {
        Err(AddressError::DifferentNetwork { actual: addr.network, expected: network })?
      }
    })
  }

  /// The network this address is intended for use on.
  pub fn network(&self) -> Network {
    self.network
  }

  /// The type of address this is.
  pub fn kind(&self) -> &AddressType {
    &self.kind
  }

  /// If this is a subaddress.
  pub fn is_subaddress(&self) -> bool {
    self.kind.is_subaddress()
  }

  /// The payment ID for this address.
  pub fn payment_id(&self) -> Option<[u8; 8]> {
    self.kind.payment_id()
  }

  /// If this address is guaranteed.
  ///
  /// A guaranteed address is one where any outputs scanned to it are guaranteed to be spendable
  /// under the hardness of various cryptographic problems (which are assumed hard). This is via
  /// a modified shared-key derivation which eliminates the burning bug.
  pub fn is_guaranteed(&self) -> bool {
    self.kind.is_guaranteed()
  }

  /// The public spend key for this address.
  pub fn spend(&self) -> EdwardsPoint {
    self.spend
  }

  /// The public view key for this address.
  pub fn view(&self) -> EdwardsPoint {
    self.view
  }
}

/// Instantiation of the Address type with Monero's network bytes.
pub type MoneroAddress = Address<{ MONERO_BYTES.to_const_generic() }>;

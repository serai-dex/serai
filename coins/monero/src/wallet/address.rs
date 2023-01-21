use core::{marker::PhantomData, fmt::Debug};
use std::string::ToString;

use thiserror::Error;

use zeroize::Zeroize;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use base58_monero::base58::{encode_check, decode_check};

/// The network this address is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum Network {
  Mainnet,
  Testnet,
  Stagenet,
}

/// The address type, supporting the officially documented addresses, along with
/// [Featured Addresses](https://gist.github.com/kayabaNerve/01c50bbc35441e0bbdcee63a9d823789).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum AddressType {
  Standard,
  Integrated([u8; 8]),
  Subaddress,
  Featured { subaddress: bool, payment_id: Option<[u8; 8]>, guaranteed: bool },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct SubaddressIndex {
  pub(crate) account: u32,
  pub(crate) address: u32,
}

impl SubaddressIndex {
  pub const fn new(account: u32, address: u32) -> Option<SubaddressIndex> {
    if (account == 0) && (address == 0) {
      return None;
    }
    Some(SubaddressIndex { account, address })
  }

  pub fn account(&self) -> u32 {
    self.account
  }

  pub fn address(&self) -> u32 {
    self.address
  }
}

/// Address specification. Used internally to create addresses.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum AddressSpec {
  Standard,
  Integrated([u8; 8]),
  Subaddress(SubaddressIndex),
  Featured { subaddress: Option<SubaddressIndex>, payment_id: Option<[u8; 8]>, guaranteed: bool },
}

impl AddressType {
  pub fn is_subaddress(&self) -> bool {
    matches!(self, AddressType::Subaddress) ||
      matches!(self, AddressType::Featured { subaddress: true, .. })
  }

  pub fn payment_id(&self) -> Option<[u8; 8]> {
    if let AddressType::Integrated(id) = self {
      Some(*id)
    } else if let AddressType::Featured { payment_id, .. } = self {
      *payment_id
    } else {
      None
    }
  }

  pub fn is_guaranteed(&self) -> bool {
    matches!(self, AddressType::Featured { guaranteed: true, .. })
  }
}

/// A type which returns the byte for a given address.
pub trait AddressBytes: Clone + Copy + PartialEq + Eq + Debug {
  fn network_bytes(network: Network) -> (u8, u8, u8, u8);
}

/// Address bytes for Monero.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MoneroAddressBytes;
impl AddressBytes for MoneroAddressBytes {
  fn network_bytes(network: Network) -> (u8, u8, u8, u8) {
    match network {
      Network::Mainnet => (18, 19, 42, 70),
      Network::Testnet => (53, 54, 63, 111),
      Network::Stagenet => (24, 25, 36, 86),
    }
  }
}

/// Address metadata.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddressMeta<B: AddressBytes> {
  _bytes: PhantomData<B>,
  pub network: Network,
  pub kind: AddressType,
}

impl<B: AddressBytes> Zeroize for AddressMeta<B> {
  fn zeroize(&mut self) {
    self.network.zeroize();
    self.kind.zeroize();
  }
}

/// Error when decoding an address.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum AddressError {
  #[error("invalid address byte")]
  InvalidByte,
  #[error("invalid address encoding")]
  InvalidEncoding,
  #[error("invalid length")]
  InvalidLength,
  #[error("invalid key")]
  InvalidKey,
  #[error("unknown features")]
  UnknownFeatures,
  #[error("different network than expected")]
  DifferentNetwork,
}

impl<B: AddressBytes> AddressMeta<B> {
  #[allow(clippy::wrong_self_convention)]
  fn to_byte(&self) -> u8 {
    let bytes = B::network_bytes(self.network);
    match self.kind {
      AddressType::Standard => bytes.0,
      AddressType::Integrated(_) => bytes.1,
      AddressType::Subaddress => bytes.2,
      AddressType::Featured { .. } => bytes.3,
    }
  }

  /// Create an address's metadata.
  pub fn new(network: Network, kind: AddressType) -> Self {
    AddressMeta { _bytes: PhantomData, network, kind }
  }

  // Returns an incomplete instantiation in the case of Integrated/Featured addresses
  fn from_byte(byte: u8) -> Result<Self, AddressError> {
    let mut meta = None;
    for network in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
      let (standard, integrated, subaddress, featured) = B::network_bytes(network);
      if let Some(kind) = match byte {
        _ if byte == standard => Some(AddressType::Standard),
        _ if byte == integrated => Some(AddressType::Integrated([0; 8])),
        _ if byte == subaddress => Some(AddressType::Subaddress),
        _ if byte == featured => {
          Some(AddressType::Featured { subaddress: false, payment_id: None, guaranteed: false })
        }
        _ => None,
      } {
        meta = Some(AddressMeta::new(network, kind));
        break;
      }
    }

    meta.ok_or(AddressError::InvalidByte)
  }

  pub fn is_subaddress(&self) -> bool {
    self.kind.is_subaddress()
  }

  pub fn payment_id(&self) -> Option<[u8; 8]> {
    self.kind.payment_id()
  }

  pub fn is_guaranteed(&self) -> bool {
    self.kind.is_guaranteed()
  }
}

/// A Monero address, composed of metadata and a spend/view key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address<B: AddressBytes> {
  pub meta: AddressMeta<B>,
  pub spend: EdwardsPoint,
  pub view: EdwardsPoint,
}

impl<B: AddressBytes> Zeroize for Address<B> {
  fn zeroize(&mut self) {
    self.meta.zeroize();
    self.spend.zeroize();
    self.view.zeroize();
  }
}

impl<B: AddressBytes> ToString for Address<B> {
  fn to_string(&self) -> String {
    let mut data = vec![self.meta.to_byte()];
    data.extend(self.spend.compress().to_bytes());
    data.extend(self.view.compress().to_bytes());
    if let AddressType::Featured { subaddress, payment_id, guaranteed } = self.meta.kind {
      // Technically should be a VarInt, yet we don't have enough features it's needed
      data.push(
        u8::from(subaddress) + (u8::from(payment_id.is_some()) << 1) + (u8::from(guaranteed) << 2),
      );
    }
    if let Some(id) = self.meta.kind.payment_id() {
      data.extend(id);
    }
    encode_check(&data).unwrap()
  }
}

impl<B: AddressBytes> Address<B> {
  pub fn new(meta: AddressMeta<B>, spend: EdwardsPoint, view: EdwardsPoint) -> Self {
    Address { meta, spend, view }
  }

  pub fn from_str_raw(s: &str) -> Result<Self, AddressError> {
    let raw = decode_check(s).map_err(|_| AddressError::InvalidEncoding)?;
    if raw.len() < (1 + 32 + 32) {
      Err(AddressError::InvalidLength)?;
    }

    let mut meta = AddressMeta::from_byte(raw[0])?;
    let spend = CompressedEdwardsY(raw[1 .. 33].try_into().unwrap())
      .decompress()
      .ok_or(AddressError::InvalidKey)?;
    let view = CompressedEdwardsY(raw[33 .. 65].try_into().unwrap())
      .decompress()
      .ok_or(AddressError::InvalidKey)?;
    let mut read = 65;

    if matches!(meta.kind, AddressType::Featured { .. }) {
      if raw[read] >= (2 << 3) {
        Err(AddressError::UnknownFeatures)?;
      }

      let subaddress = (raw[read] & 1) == 1;
      let integrated = ((raw[read] >> 1) & 1) == 1;
      let guaranteed = ((raw[read] >> 2) & 1) == 1;

      meta.kind = AddressType::Featured {
        subaddress,
        payment_id: Some([0; 8]).filter(|_| integrated),
        guaranteed,
      };
      read += 1;
    }

    // Update read early so we can verify the length
    if meta.kind.payment_id().is_some() {
      read += 8;
    }
    if raw.len() != read {
      Err(AddressError::InvalidLength)?;
    }

    if let AddressType::Integrated(ref mut id) = meta.kind {
      id.copy_from_slice(&raw[(read - 8) .. read]);
    }
    if let AddressType::Featured { payment_id: Some(ref mut id), .. } = meta.kind {
      id.copy_from_slice(&raw[(read - 8) .. read]);
    }

    Ok(Address { meta, spend, view })
  }

  pub fn from_str(network: Network, s: &str) -> Result<Self, AddressError> {
    Self::from_str_raw(s).and_then(|addr| {
      if addr.meta.network == network {
        Ok(addr)
      } else {
        Err(AddressError::DifferentNetwork)?
      }
    })
  }

  pub fn network(&self) -> Network {
    self.meta.network
  }

  pub fn is_subaddress(&self) -> bool {
    self.meta.is_subaddress()
  }

  pub fn payment_id(&self) -> Option<[u8; 8]> {
    self.meta.payment_id()
  }

  pub fn is_guaranteed(&self) -> bool {
    self.meta.is_guaranteed()
  }
}

/// Instantiation of the Address type with Monero's network bytes.
pub type MoneroAddress = Address<MoneroAddressBytes>;
// Allow re-interpreting of an arbitrary address as a monero address so it can be used with the
// rest of this library. Doesn't use From as it was conflicting with From<T> for T.
impl MoneroAddress {
  pub fn from<B: AddressBytes>(address: Address<B>) -> MoneroAddress {
    MoneroAddress::new(
      AddressMeta::new(address.meta.network, address.meta.kind),
      address.spend,
      address.view,
    )
  }
}

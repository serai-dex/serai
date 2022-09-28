use std::string::ToString;

use thiserror::Error;

use zeroize::Zeroize;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use base58_monero::base58::{encode_check, decode_check};

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
  Featured(bool, Option<[u8; 8]>, bool),
}

impl AddressType {
  fn network_bytes(network: Network) -> (u8, u8, u8, u8) {
    match network {
      Network::Mainnet => (18, 19, 42, 70),
      Network::Testnet => (53, 54, 63, 111),
      Network::Stagenet => (24, 25, 36, 86),
    }
  }

  pub fn subaddress(&self) -> bool {
    matches!(self, AddressType::Subaddress) || matches!(self, AddressType::Featured(true, ..))
  }

  pub fn payment_id(&self) -> Option<[u8; 8]> {
    if let AddressType::Integrated(id) = self {
      Some(*id)
    } else if let AddressType::Featured(_, id, _) = self {
      *id
    } else {
      None
    }
  }

  pub fn guaranteed(&self) -> bool {
    matches!(self, AddressType::Featured(_, _, true))
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct AddressMeta {
  pub network: Network,
  pub kind: AddressType,
}

#[derive(Clone, Error, Debug)]
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

impl AddressMeta {
  #[allow(clippy::wrong_self_convention)]
  fn to_byte(&self) -> u8 {
    let bytes = AddressType::network_bytes(self.network);
    match self.kind {
      AddressType::Standard => bytes.0,
      AddressType::Integrated(_) => bytes.1,
      AddressType::Subaddress => bytes.2,
      AddressType::Featured(..) => bytes.3,
    }
  }

  // Returns an incomplete type in the case of Integrated/Featured addresses
  fn from_byte(byte: u8) -> Result<AddressMeta, AddressError> {
    let mut meta = None;
    for network in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
      let (standard, integrated, subaddress, featured) = AddressType::network_bytes(network);
      if let Some(kind) = match byte {
        _ if byte == standard => Some(AddressType::Standard),
        _ if byte == integrated => Some(AddressType::Integrated([0; 8])),
        _ if byte == subaddress => Some(AddressType::Subaddress),
        _ if byte == featured => Some(AddressType::Featured(false, None, false)),
        _ => None,
      } {
        meta = Some(AddressMeta { network, kind });
        break;
      }
    }

    meta.ok_or(AddressError::InvalidByte)
  }

  pub fn subaddress(&self) -> bool {
    self.kind.subaddress()
  }

  pub fn payment_id(&self) -> Option<[u8; 8]> {
    self.kind.payment_id()
  }

  pub fn guaranteed(&self) -> bool {
    self.kind.guaranteed()
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Address {
  pub meta: AddressMeta,
  pub spend: EdwardsPoint,
  pub view: EdwardsPoint,
}

impl ToString for Address {
  fn to_string(&self) -> String {
    let mut data = vec![self.meta.to_byte()];
    data.extend(self.spend.compress().to_bytes());
    data.extend(self.view.compress().to_bytes());
    if let AddressType::Featured(subaddress, payment_id, guaranteed) = self.meta.kind {
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

impl Address {
  pub fn new(meta: AddressMeta, spend: EdwardsPoint, view: EdwardsPoint) -> Address {
    Address { meta, spend, view }
  }

  pub fn from_str_raw(s: &str) -> Result<Address, AddressError> {
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

    if matches!(meta.kind, AddressType::Featured(..)) {
      if raw[read] >= (2 << 3) {
        Err(AddressError::UnknownFeatures)?;
      }

      let subaddress = (raw[read] & 1) == 1;
      let integrated = ((raw[read] >> 1) & 1) == 1;
      let guaranteed = ((raw[read] >> 2) & 1) == 1;

      meta.kind =
        AddressType::Featured(subaddress, Some([0; 8]).filter(|_| integrated), guaranteed);
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
    if let AddressType::Featured(_, Some(ref mut id), _) = meta.kind {
      id.copy_from_slice(&raw[(read - 8) .. read]);
    }

    Ok(Address { meta, spend, view })
  }

  pub fn from_str(s: &str, network: Network) -> Result<Address, AddressError> {
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

  pub fn subaddress(&self) -> bool {
    self.meta.subaddress()
  }

  pub fn payment_id(&self) -> Option<[u8; 8]> {
    self.meta.payment_id()
  }

  pub fn guaranteed(&self) -> bool {
    self.meta.guaranteed()
  }
}

use std::string::ToString;

use thiserror::Error;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::{EdwardsPoint, CompressedEdwardsY}};

use base58_monero::base58::{encode_check, decode_check};

use crate::wallet::ViewPair;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
  Mainnet,
  Testnet,
  Stagenet
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressType {
  Standard,
  Integrated([u8; 8]),
  Subaddress
}

impl AddressType {
  fn network_bytes(network: Network) -> (u8, u8, u8) {
    match network {
      Network::Mainnet => (18, 19, 42),
      Network::Testnet => (53, 54, 63),
      Network::Stagenet => (24, 25, 36)
    }
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddressMeta {
  pub network: Network,
  pub kind: AddressType,
  pub guaranteed: bool
}

#[derive(Clone, Error, Debug)]
pub enum AddressError {
  #[error("invalid address byte")]
  InvalidByte,
  #[error("invalid address encoding")]
  InvalidEncoding,
  #[error("invalid length")]
  InvalidLength,
  #[error("different network than expected")]
  DifferentNetwork,
  #[error("invalid key")]
  InvalidKey
}

impl AddressMeta {
  fn to_byte(&self) -> u8 {
    let bytes = AddressType::network_bytes(self.network);
    let byte = match self.kind {
      AddressType::Standard => bytes.0,
      AddressType::Integrated(_) => bytes.1,
      AddressType::Subaddress => bytes.2
    };
    byte | (if self.guaranteed { 1 << 7 } else { 0 })
  }

  // Returns an incomplete type in the case of Integrated addresses
  fn from_byte(byte: u8) -> Result<AddressMeta, AddressError> {
    let actual = byte & 0b01111111;
    let guaranteed = (byte >> 7) == 1;

    let mut meta = None;
    for network in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
      let (standard, integrated, subaddress) = AddressType::network_bytes(network);
      if let Some(kind) = match actual {
        _ if actual == standard => Some(AddressType::Standard),
        _ if actual == integrated => Some(AddressType::Integrated([0; 8])),
        _ if actual == subaddress => Some(AddressType::Subaddress),
        _ => None
      } {
        meta = Some(AddressMeta { network, kind, guaranteed });
        break;
      }
    }

    meta.ok_or(AddressError::InvalidByte)
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
  pub meta: AddressMeta,
  pub spend: EdwardsPoint,
  pub view: EdwardsPoint
}

impl ViewPair {
  pub fn address(&self, network: Network, kind: AddressType, guaranteed: bool) -> Address {
    Address {
      meta: AddressMeta {
        network,
        kind,
        guaranteed
      },
      spend: self.spend,
      view: &self.view * &ED25519_BASEPOINT_TABLE
    }
  }
}

impl ToString for Address {
  fn to_string(&self) -> String {
    let mut data = vec![self.meta.to_byte()];
    data.extend(self.spend.compress().to_bytes());
    data.extend(self.view.compress().to_bytes());
    if let AddressType::Integrated(id) = self.meta.kind {
      data.extend(id);
    }
    encode_check(&data).unwrap()
  }
}

impl Address {
  pub fn from_str(s: &str, network: Network) -> Result<Self, AddressError> {
    let raw = decode_check(s).map_err(|_| AddressError::InvalidEncoding)?;
    if raw.len() == 1 {
      Err(AddressError::InvalidLength)?;
    }

    let mut meta = AddressMeta::from_byte(raw[0])?;
    if meta.network != network {
      Err(AddressError::DifferentNetwork)?;
    }

    let len = match meta.kind {
      AddressType::Standard | AddressType::Subaddress => 65,
      AddressType::Integrated(_) => 73
    };
    if raw.len() != len {
      Err(AddressError::InvalidLength)?;
    }

    let spend = CompressedEdwardsY(raw[1 .. 33].try_into().unwrap()).decompress().ok_or(AddressError::InvalidKey)?;
    let view = CompressedEdwardsY(raw[33 .. 65].try_into().unwrap()).decompress().ok_or(AddressError::InvalidKey)?;

    if let AddressType::Integrated(ref mut payment_id) = meta.kind {
      payment_id.copy_from_slice(&raw[65 .. 73]);
    }

    Ok(Address { meta, spend, view })
  }
}

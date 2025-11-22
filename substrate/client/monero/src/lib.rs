#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{str::FromStr, fmt};

use ciphersuite::{group::GroupEncoding, GroupIo};
use dalek_ff_group::Ed25519;

use monero_ed25519::{CompressedPoint, Point};
use monero_address::{Network, AddressType as MoneroAddressType, MoneroAddress};

use serai_primitives::address::ExternalAddress;

#[allow(non_snake_case)]
fn read_G(reader: &mut impl borsh::io::Read) -> borsh::io::Result<Point> {
  // We use `Ed25519::read_G` for the strong canonicalization requirements before using
  //` monero-ed25519` for the actual values
  CompressedPoint::from(Ed25519::read_G(reader)?.to_bytes()).decompress().ok_or_else(|| {
    borsh::io::Error::other(
      "canonically-encoded torsion-free point was rejected by `monero-ed25519`",
    )
  })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AddressType {
  Legacy,
  Subaddress,
}

/// A representation of a Monero address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
  kind: AddressType,
  spend: Point,
  view: Point,
}

fn byte_for_kind(kind: AddressType) -> u8 {
  match kind {
    AddressType::Legacy => 0,
    AddressType::Subaddress => 1,
  }
}

impl borsh::BorshSerialize for Address {
  fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
    writer.write_all(&[byte_for_kind(self.kind)])?;
    writer.write_all(&self.spend.compress().to_bytes())?;
    writer.write_all(&self.view.compress().to_bytes())
  }
}
impl borsh::BorshDeserialize for Address {
  fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
    let mut kind_byte = [0xff];
    reader.read_exact(&mut kind_byte)?;
    let kind_byte = kind_byte[0];
    let kind = match kind_byte {
      0 => AddressType::Legacy,
      1 => AddressType::Subaddress,
      _ => Err(borsh::io::Error::other("unrecognized type"))?,
    };
    let spend = read_G(reader)?;
    let view = read_G(reader)?;
    Ok(Self { kind, spend, view })
  }
}

impl TryFrom<MoneroAddress> for Address {
  type Error = ();
  fn try_from(address: MoneroAddress) -> Result<Self, ()> {
    let spend = address.spend().compress().to_bytes();
    let view = address.view().compress().to_bytes();
    let kind = match address.kind() {
      MoneroAddressType::Legacy => AddressType::Legacy,
      MoneroAddressType::Subaddress => AddressType::Subaddress,
      MoneroAddressType::LegacyIntegrated(_) | MoneroAddressType::Featured { .. } => Err(())?,
    };
    Ok(Address {
      kind,
      spend: read_G(&mut spend.as_slice()).map_err(|_| ())?,
      view: read_G(&mut view.as_slice()).map_err(|_| ())?,
    })
  }
}

impl From<Address> for MoneroAddress {
  fn from(address: Address) -> MoneroAddress {
    let kind = match address.kind {
      AddressType::Legacy => MoneroAddressType::Legacy,
      AddressType::Subaddress => MoneroAddressType::Subaddress,
    };
    MoneroAddress::new(Network::Mainnet, kind, address.spend, address.view)
  }
}

impl TryFrom<ExternalAddress> for Address {
  type Error = ();
  fn try_from(data: ExternalAddress) -> Result<Address, ()> {
    // Decode as an Address
    let mut data = data.as_ref();
    let address =
      <Address as borsh::BorshDeserialize>::deserialize_reader(&mut data).map_err(|_| ())?;
    if !data.is_empty() {
      Err(())?
    }
    Ok(address)
  }
}
impl From<Address> for ExternalAddress {
  fn from(address: Address) -> ExternalAddress {
    // This is 65 bytes which is less than MAX_ADDRESS_LEN
    ExternalAddress::try_from(borsh::to_vec(&address).unwrap()).unwrap()
  }
}

impl FromStr for Address {
  type Err = ();
  fn from_str(str: &str) -> Result<Address, ()> {
    let Ok(address) = MoneroAddress::from_str(Network::Mainnet, str) else { Err(())? };
    Address::try_from(address)
  }
}

impl fmt::Display for Address {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    MoneroAddress::from(*self).fmt(f)
  }
}

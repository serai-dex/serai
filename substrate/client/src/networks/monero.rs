use core::{str::FromStr, fmt};

use ciphersuite::{Ciphersuite, Ed25519};

use monero_address::{Network, AddressType as MoneroAddressType, MoneroAddress};

use crate::primitives::ExternalAddress;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AddressType {
  Legacy,
  Subaddress,
  Featured(u8),
}

/// A representation of a Monero address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
  kind: AddressType,
  spend: <Ed25519 as Ciphersuite>::G,
  view: <Ed25519 as Ciphersuite>::G,
}

fn byte_for_kind(kind: AddressType) -> u8 {
  // We use the second and third highest bits for the type
  // This leaves the top bit open for interpretation as a VarInt later
  match kind {
    AddressType::Legacy => 0,
    AddressType::Subaddress => 1 << 5,
    AddressType::Featured(flags) => {
      // The flags only take up the low three bits
      debug_assert!(flags <= 0b111);
      (2 << 5) | flags
    }
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
    let kind = match kind_byte >> 5 {
      0 => AddressType::Legacy,
      1 => AddressType::Subaddress,
      2 => AddressType::Featured(kind_byte & 0b111),
      _ => Err(borsh::io::Error::other("unrecognized type"))?,
    };
    // Check this wasn't malleated
    if byte_for_kind(kind) != kind_byte {
      Err(borsh::io::Error::other("malleated type byte"))?;
    }
    let spend = Ed25519::read_G(reader)?;
    let view = Ed25519::read_G(reader)?;
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
      MoneroAddressType::LegacyIntegrated(_) => Err(())?,
      MoneroAddressType::Subaddress => AddressType::Subaddress,
      MoneroAddressType::Featured { subaddress, payment_id, guaranteed } => {
        if payment_id.is_some() {
          Err(())?
        }
        // This maintains the same bit layout as featured addresses use
        AddressType::Featured(u8::from(*subaddress) + (u8::from(*guaranteed) << 2))
      }
    };
    Ok(Address {
      kind,
      spend: Ed25519::read_G(&mut spend.as_slice()).map_err(|_| ())?,
      view: Ed25519::read_G(&mut view.as_slice()).map_err(|_| ())?,
    })
  }
}

impl From<Address> for MoneroAddress {
  fn from(address: Address) -> MoneroAddress {
    let kind = match address.kind {
      AddressType::Legacy => MoneroAddressType::Legacy,
      AddressType::Subaddress => MoneroAddressType::Subaddress,
      AddressType::Featured(features) => {
        debug_assert!(features <= 0b111);
        let subaddress = (features & 1) != 0;
        let integrated = (features & (1 << 1)) != 0;
        debug_assert!(!integrated);
        let guaranteed = (features & (1 << 2)) != 0;
        MoneroAddressType::Featured { subaddress, payment_id: None, guaranteed }
      }
    };
    MoneroAddress::new(Network::Mainnet, kind, address.spend.0, address.view.0)
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
    ExternalAddress::new(borsh::to_vec(&address).unwrap()).unwrap()
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

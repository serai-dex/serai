use core::{str::FromStr, fmt};

use scale::{Encode, Decode};

use ciphersuite::{Ciphersuite, Ed25519};

use monero_wallet::address::{AddressError, Network, AddressType, AddressMeta, MoneroAddress};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Address(MoneroAddress);
impl Address {
  pub fn new(address: MoneroAddress) -> Option<Address> {
    if address.payment_id().is_some() {
      return None;
    }
    Some(Address(address))
  }
}

impl FromStr for Address {
  type Err = AddressError;
  fn from_str(str: &str) -> Result<Address, AddressError> {
    MoneroAddress::from_str(Network::Mainnet, str).map(Address)
  }
}

impl fmt::Display for Address {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(f)
  }
}

// SCALE-encoded variant of Monero addresses.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
enum EncodedAddressType {
  Standard,
  Subaddress,
  Featured(u8),
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
struct EncodedAddress {
  kind: EncodedAddressType,
  spend: [u8; 32],
  view: [u8; 32],
}

impl TryFrom<Vec<u8>> for Address {
  type Error = ();
  fn try_from(data: Vec<u8>) -> Result<Address, ()> {
    // Decode as SCALE
    let addr = EncodedAddress::decode(&mut data.as_ref()).map_err(|_| ())?;
    // Convert over
    Ok(Address(MoneroAddress::new(
      AddressMeta::new(
        Network::Mainnet,
        match addr.kind {
          EncodedAddressType::Standard => AddressType::Standard,
          EncodedAddressType::Subaddress => AddressType::Subaddress,
          EncodedAddressType::Featured(flags) => {
            let subaddress = (flags & 1) != 0;
            let integrated = (flags & (1 << 1)) != 0;
            let guaranteed = (flags & (1 << 2)) != 0;
            if integrated {
              Err(())?;
            }
            AddressType::Featured { subaddress, payment_id: None, guaranteed }
          }
        },
      ),
      Ed25519::read_G::<&[u8]>(&mut addr.spend.as_ref()).map_err(|_| ())?.0,
      Ed25519::read_G::<&[u8]>(&mut addr.view.as_ref()).map_err(|_| ())?.0,
    )))
  }
}

#[allow(clippy::from_over_into)]
impl Into<MoneroAddress> for Address {
  fn into(self) -> MoneroAddress {
    self.0
  }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Address {
  fn into(self) -> Vec<u8> {
    EncodedAddress {
      kind: match self.0.meta.kind {
        AddressType::Standard => EncodedAddressType::Standard,
        AddressType::Subaddress => EncodedAddressType::Subaddress,
        AddressType::Integrated(_) => panic!("integrated address became Serai Monero address"),
        AddressType::Featured { subaddress, payment_id: _, guaranteed } => {
          EncodedAddressType::Featured(u8::from(subaddress) + (u8::from(guaranteed) << 2))
        }
      },
      spend: self.0.spend.compress().0,
      view: self.0.view.compress().0,
    }
    .encode()
  }
}

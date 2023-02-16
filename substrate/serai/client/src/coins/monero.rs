use core::str::FromStr;

use scale::{Encode, Decode};

use ciphersuite::{Ciphersuite, Ed25519};

use monero_serai::wallet::address::{AddressError, Network, AddressType, AddressMeta, MoneroAddress};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Address(pub MoneroAddress);

impl FromStr for Address {
  type Err = AddressError;
  fn from_str(str: &str) -> Result<Address, AddressError> {
    MoneroAddress::from_str_raw(str).map(Address)
  }
}

impl ToString for Address {
  fn to_string(&self) -> String {
    self.0.to_string()
  }
}

// SCALE-encoded variant of Monero addresses.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
enum EncodedAddressType {
  Standard,
  Integrated([u8; 8]),
  Subaddress,
  Featured(u8, Option<[u8; 8]>),
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
          EncodedAddressType::Integrated(id) => AddressType::Integrated(id),
          EncodedAddressType::Subaddress => AddressType::Subaddress,
          EncodedAddressType::Featured(flags, payment_id) => {
            let subaddress = (flags & 1) != 0;
            let integrated = (flags & (1 << 1)) != 0;
            let guaranteed = (flags & (1 << 2)) != 0;
            if integrated != payment_id.is_some() {
              Err(())?;
            }
            AddressType::Featured { subaddress, payment_id, guaranteed }
          }
        },
      ),
      Ed25519::read_G(&mut addr.spend.as_ref()).map_err(|_| ())?.0,
      Ed25519::read_G(&mut addr.view.as_ref()).map_err(|_| ())?.0,
    )))
  }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Address {
  fn into(self) -> Vec<u8> {
    EncodedAddress {
      kind: match self.0.meta.kind {
        AddressType::Standard => EncodedAddressType::Standard,
        AddressType::Integrated(payment_id) => EncodedAddressType::Integrated(payment_id),
        AddressType::Subaddress => EncodedAddressType::Subaddress,
        AddressType::Featured { subaddress, payment_id, guaranteed } => {
          EncodedAddressType::Featured(
            u8::from(subaddress) +
              (u8::from(payment_id.is_some()) << 1) +
              (u8::from(guaranteed) << 2),
            payment_id,
          )
        }
      },
      spend: self.0.spend.compress().0,
      view: self.0.view.compress().0,
    }
    .encode()
  }
}

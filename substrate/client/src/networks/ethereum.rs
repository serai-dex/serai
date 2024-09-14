use core::{str::FromStr, fmt};

use borsh::{BorshSerialize, BorshDeserialize};

use crate::primitives::ExternalAddress;

/// A representation of an Ethereum address.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Address([u8; 20]);

impl From<[u8; 20]> for Address {
  fn from(address: [u8; 20]) -> Self {
    Self(address)
  }
}

impl From<Address> for [u8; 20] {
  fn from(address: Address) -> Self {
    address.0
  }
}

impl TryFrom<ExternalAddress> for Address {
  type Error = ();
  fn try_from(data: ExternalAddress) -> Result<Address, ()> {
    Ok(Self(data.as_ref().try_into().map_err(|_| ())?))
  }
}
impl From<Address> for ExternalAddress {
  fn from(address: Address) -> ExternalAddress {
    // This is 20 bytes which is less than MAX_ADDRESS_LEN
    ExternalAddress::new(address.0.to_vec()).unwrap()
  }
}

impl FromStr for Address {
  type Err = ();
  fn from_str(str: &str) -> Result<Address, ()> {
    let Some(address) = str.strip_prefix("0x") else { Err(())? };
    if address.len() != 40 {
      Err(())?
    };
    Ok(Self(hex::decode(address.to_lowercase()).map_err(|_| ())?.try_into().unwrap()))
  }
}

impl fmt::Display for Address {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "0x{}", hex::encode(self.0))
  }
}

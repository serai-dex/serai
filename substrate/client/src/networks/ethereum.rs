use core::str::FromStr;
use std::io::Read;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::primitives::{MAX_ADDRESS_LEN, ExternalAddress};

/// THe maximum amount of gas an address is allowed to specify as its gas limit.
///
/// Payments to an address with a gas limit which exceed this value will be dropped entirely.
pub const ADDRESS_GAS_LIMIT: u32 = 950_000;

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ContractDeployment {
  /// The gas limit to use for this contract's execution.
  ///
  /// THis MUST be less than the Serai gas limit. The cost of it will be deducted from the amount
  /// transferred.
  gas_limit: u32,
  /// The initialization code of the contract to deploy.
  ///
  /// This contract will be deployed (executing the initialization code). No further calls will
  /// be made.
  code: Vec<u8>,
}

/// A contract to deploy, enabling executing arbitrary code.
impl ContractDeployment {
  pub fn new(gas_limit: u32, code: Vec<u8>) -> Option<Self> {
    // Check the gas limit is less the address gas limit
    if gas_limit > ADDRESS_GAS_LIMIT {
      None?;
    }

    // The max address length, minus the type byte, minus the size of the gas
    const MAX_CODE_LEN: usize = (MAX_ADDRESS_LEN as usize) - (1 + core::mem::size_of::<u32>());
    if code.len() > MAX_CODE_LEN {
      None?;
    }

    Some(Self { gas_limit, code })
  }

  pub fn gas_limit(&self) -> u32 {
    self.gas_limit
  }
  pub fn code(&self) -> &[u8] {
    &self.code
  }
}

/// A representation of an Ethereum address.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Address {
  /// A traditional address.
  Address([u8; 20]),
  /// A contract to deploy, enabling executing arbitrary code.
  Contract(ContractDeployment),
}

impl From<[u8; 20]> for Address {
  fn from(address: [u8; 20]) -> Self {
    Address::Address(address)
  }
}

impl TryFrom<ExternalAddress> for Address {
  type Error = ();
  fn try_from(data: ExternalAddress) -> Result<Address, ()> {
    let mut kind = [0xff];
    let mut reader: &[u8] = data.as_ref();
    reader.read_exact(&mut kind).map_err(|_| ())?;
    Ok(match kind[0] {
      0 => {
        let mut address = [0xff; 20];
        reader.read_exact(&mut address).map_err(|_| ())?;
        Address::Address(address)
      }
      1 => {
        let mut gas_limit = [0xff; 4];
        reader.read_exact(&mut gas_limit).map_err(|_| ())?;
        Address::Contract(ContractDeployment {
          gas_limit: {
            let gas_limit = u32::from_le_bytes(gas_limit);
            if gas_limit > ADDRESS_GAS_LIMIT {
              Err(())?;
            }
            gas_limit
          },
          // The code is whatever's left since the ExternalAddress is a delimited container of
          // appropriately bounded length
          code: reader.to_vec(),
        })
      }
      _ => Err(())?,
    })
  }
}
impl From<Address> for ExternalAddress {
  fn from(address: Address) -> ExternalAddress {
    let mut res = Vec::with_capacity(1 + 20);
    match address {
      Address::Address(address) => {
        res.push(0);
        res.extend(&address);
      }
      Address::Contract(ContractDeployment { gas_limit, code }) => {
        res.push(1);
        res.extend(&gas_limit.to_le_bytes());
        res.extend(&code);
      }
    }
    // We only construct addresses whose code is small enough this can safely be constructed
    ExternalAddress::new(res).unwrap()
  }
}

impl FromStr for Address {
  type Err = ();
  fn from_str(str: &str) -> Result<Address, ()> {
    let Some(address) = str.strip_prefix("0x") else { Err(())? };
    if address.len() != 40 {
      Err(())?
    };
    Ok(Address::Address(
      hex::decode(address.to_lowercase()).map_err(|_| ())?.try_into().map_err(|_| ())?,
    ))
  }
}

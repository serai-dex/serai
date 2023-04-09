use core::str::FromStr;

use scale::{Encode, Decode};

use bitcoin::{
  hashes::{Hash as HashTrait, hash160::Hash},
  PubkeyHash, ScriptHash,
  network::constants::Network,
  address::{
    Error, WitnessVersion, Payload, WitnessProgram, NetworkChecked, Address as BAddressGeneric,
  },
};

type BAddress = BAddressGeneric<NetworkChecked>;

#[derive(Clone, Eq, Debug)]
pub struct Address(pub BAddress);

impl PartialEq for Address {
  fn eq(&self, other: &Self) -> bool {
    self.0.payload == other.0.payload
  }
}

impl FromStr for Address {
  type Err = Error;
  fn from_str(str: &str) -> Result<Address, Error> {
    let mut original_address = BAddressGeneric::from_str(str)?;
    // Standardize the network
    original_address.network = Network::Bitcoin;
    let address = original_address
      .clone()
      .require_network(Network::Bitcoin)
      .expect("network wasn't mainnet despite overriding network");

    // Also check this isn't caching the string internally
    if BAddressGeneric::from_str(&address.to_string())? != original_address {
      // TODO: Make this an error?
      panic!("Address::from_str(address.to_string()) != address for Bitcoin");
    }

    Ok(Address(address))
  }
}

impl ToString for Address {
  fn to_string(&self) -> String {
    self.0.to_string()
  }
}

// SCALE-encoded variant of Monero addresses.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
enum EncodedAddress {
  P2PKH([u8; 20]),
  P2SH([u8; 20]),
  P2WPKH([u8; 20]),
  P2WSH([u8; 32]),
  P2TR([u8; 32]),
}

impl TryFrom<Vec<u8>> for Address {
  type Error = ();
  fn try_from(data: Vec<u8>) -> Result<Address, ()> {
    Ok(Address(BAddress::new(
      Network::Bitcoin,
      match EncodedAddress::decode(&mut data.as_ref()).map_err(|_| ())? {
        EncodedAddress::P2PKH(hash) => {
          Payload::PubkeyHash(PubkeyHash::from_raw_hash(Hash::from_byte_array(hash)))
        }
        EncodedAddress::P2SH(hash) => {
          Payload::ScriptHash(ScriptHash::from_raw_hash(Hash::from_byte_array(hash)))
        }
        EncodedAddress::P2WPKH(hash) => {
          Payload::WitnessProgram(WitnessProgram::new(WitnessVersion::V0, hash).unwrap())
        }
        EncodedAddress::P2WSH(hash) => {
          Payload::WitnessProgram(WitnessProgram::new(WitnessVersion::V0, hash).unwrap())
        }
        EncodedAddress::P2TR(key) => {
          Payload::WitnessProgram(WitnessProgram::new(WitnessVersion::V1, key).unwrap())
        }
      },
    )))
  }
}

#[allow(clippy::from_over_into)]
impl TryInto<Vec<u8>> for Address {
  type Error = ();
  fn try_into(self) -> Result<Vec<u8>, ()> {
    Ok(
      (match self.0.payload {
        Payload::PubkeyHash(hash) => EncodedAddress::P2PKH(*hash.as_raw_hash().as_byte_array()),
        Payload::ScriptHash(hash) => EncodedAddress::P2SH(*hash.as_raw_hash().as_byte_array()),
        Payload::WitnessProgram(program) => match program.version() {
          WitnessVersion::V0 => {
            let program = program.program();
            if program.len() == 20 {
              let mut buf = [0; 20];
              buf.copy_from_slice(program.as_ref());
              EncodedAddress::P2WPKH(buf)
            } else if program.len() == 32 {
              let mut buf = [0; 32];
              buf.copy_from_slice(program.as_ref());
              EncodedAddress::P2WSH(buf)
            } else {
              Err(())?
            }
          }
          WitnessVersion::V1 => {
            let program_ref: &[u8] = program.program().as_ref();
            EncodedAddress::P2TR(program_ref.try_into().map_err(|_| ())?)
          }
          _ => Err(())?,
        },
        _ => Err(())?,
      })
      .encode(),
    )
  }
}

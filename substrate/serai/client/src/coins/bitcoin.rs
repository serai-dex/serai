use core::str::FromStr;

use scale::{Encode, Decode};

use bitcoin::{
  hashes::{Hash as HashTrait, hash160::Hash},
  PubkeyHash, ScriptHash,
  network::constants::Network,
  util::address::{Error, WitnessVersion, Payload, Address as BAddress},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Address(pub BAddress);

impl FromStr for Address {
  type Err = Error;
  fn from_str(str: &str) -> Result<Address, Error> {
    BAddress::from_str(str).map(Address)
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
    Ok(Address(BAddress {
      network: Network::Bitcoin,
      payload: match EncodedAddress::decode(&mut data.as_ref()).map_err(|_| ())? {
        EncodedAddress::P2PKH(hash) => {
          Payload::PubkeyHash(PubkeyHash::from_hash(Hash::from_inner(hash)))
        }
        EncodedAddress::P2SH(hash) => {
          Payload::ScriptHash(ScriptHash::from_hash(Hash::from_inner(hash)))
        }
        EncodedAddress::P2WPKH(hash) => {
          Payload::WitnessProgram { version: WitnessVersion::V0, program: hash.to_vec() }
        }
        EncodedAddress::P2WSH(hash) => {
          Payload::WitnessProgram { version: WitnessVersion::V0, program: hash.to_vec() }
        }
        EncodedAddress::P2TR(key) => {
          Payload::WitnessProgram { version: WitnessVersion::V1, program: key.to_vec() }
        }
      },
    }))
  }
}

#[allow(clippy::from_over_into)]
impl TryInto<Vec<u8>> for Address {
  type Error = ();
  fn try_into(self) -> Result<Vec<u8>, ()> {
    Ok(
      (match self.0.payload {
        Payload::PubkeyHash(hash) => EncodedAddress::P2PKH(hash.as_hash().into_inner()),
        Payload::ScriptHash(hash) => EncodedAddress::P2SH(hash.as_hash().into_inner()),
        Payload::WitnessProgram { version: WitnessVersion::V0, program } => {
          if program.len() == 20 {
            EncodedAddress::P2WPKH(program.try_into().map_err(|_| ())?)
          } else if program.len() == 32 {
            EncodedAddress::P2WSH(program.try_into().map_err(|_| ())?)
          } else {
            Err(())?
          }
        }
        Payload::WitnessProgram { version: WitnessVersion::V1, program } => {
          EncodedAddress::P2TR(program.try_into().map_err(|_| ())?)
        }
        _ => Err(())?,
      })
      .encode(),
    )
  }
}

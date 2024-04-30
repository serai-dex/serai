use core::{str::FromStr, fmt};

use scale::{Encode, Decode};

use bitcoin::{
  hashes::{Hash as HashTrait, hash160::Hash},
  PubkeyHash, ScriptHash,
  network::Network,
  WitnessVersion, WitnessProgram,
  address::{Error, Payload, NetworkChecked, Address as BAddressGeneric},
};

type BAddress = BAddressGeneric<NetworkChecked>;

#[derive(Clone, Eq, Debug)]
pub struct Address(BAddress);

impl PartialEq for Address {
  fn eq(&self, other: &Self) -> bool {
    // Since Serai defines the Bitcoin-address specification as a variant of the payload alone,
    // define equivalency as the payload alone
    self.0.payload() == other.0.payload()
  }
}

impl FromStr for Address {
  type Err = Error;
  fn from_str(str: &str) -> Result<Address, Error> {
    Address::new(
      BAddressGeneric::from_str(str)
        .map_err(|_| Error::UnrecognizedScript)?
        .require_network(Network::Bitcoin)?,
    )
    .ok_or(Error::UnrecognizedScript)
  }
}

impl fmt::Display for Address {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(f)
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

fn try_to_vec(addr: &Address) -> Result<Vec<u8>, ()> {
  Ok(
    (match addr.0.payload() {
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

impl From<Address> for Vec<u8> {
  fn from(addr: Address) -> Vec<u8> {
    // Safe since only encodable addresses can be created
    try_to_vec(&addr).unwrap()
  }
}

impl From<Address> for BAddress {
  fn from(addr: Address) -> BAddress {
    addr.0
  }
}

impl AsRef<BAddress> for Address {
  fn as_ref(&self) -> &BAddress {
    &self.0
  }
}

impl Address {
  pub fn new(address: BAddress) -> Option<Self> {
    let res = Self(address);
    if try_to_vec(&res).is_ok() {
      return Some(res);
    }
    None
  }
}

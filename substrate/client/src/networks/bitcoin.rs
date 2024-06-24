use core::{str::FromStr, fmt};

use scale::{Encode, Decode};

use bitcoin::{
  hashes::{Hash as HashTrait, hash160::Hash},
  PubkeyHash, ScriptHash,
  network::Network,
  WitnessVersion, WitnessProgram, ScriptBuf,
  address::{AddressType, NetworkChecked, Address as BAddress},
};

#[derive(Clone, Eq, Debug)]
pub struct Address(ScriptBuf);

impl PartialEq for Address {
  fn eq(&self, other: &Self) -> bool {
    // Since Serai defines the Bitcoin-address specification as a variant of the script alone,
    // define equivalency as the script alone
    self.0 == other.0
  }
}

impl From<Address> for ScriptBuf {
  fn from(addr: Address) -> ScriptBuf {
    addr.0
  }
}

impl FromStr for Address {
  type Err = ();
  fn from_str(str: &str) -> Result<Address, ()> {
    Address::new(
      BAddress::from_str(str)
        .map_err(|_| ())?
        .require_network(Network::Bitcoin)
        .map_err(|_| ())?
        .script_pubkey(),
    )
    .ok_or(())
  }
}

impl fmt::Display for Address {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    BAddress::<NetworkChecked>::from_script(&self.0, Network::Bitcoin)
      .map_err(|_| fmt::Error)?
      .fmt(f)
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
    Ok(Address(match EncodedAddress::decode(&mut data.as_ref()).map_err(|_| ())? {
      EncodedAddress::P2PKH(hash) => {
        ScriptBuf::new_p2pkh(&PubkeyHash::from_raw_hash(Hash::from_byte_array(hash)))
      }
      EncodedAddress::P2SH(hash) => {
        ScriptBuf::new_p2sh(&ScriptHash::from_raw_hash(Hash::from_byte_array(hash)))
      }
      EncodedAddress::P2WPKH(hash) => {
        ScriptBuf::new_witness_program(&WitnessProgram::new(WitnessVersion::V0, &hash).unwrap())
      }
      EncodedAddress::P2WSH(hash) => {
        ScriptBuf::new_witness_program(&WitnessProgram::new(WitnessVersion::V0, &hash).unwrap())
      }
      EncodedAddress::P2TR(key) => {
        ScriptBuf::new_witness_program(&WitnessProgram::new(WitnessVersion::V1, &key).unwrap())
      }
    }))
  }
}

fn try_to_vec(addr: &Address) -> Result<Vec<u8>, ()> {
  let parsed_addr =
    BAddress::<NetworkChecked>::from_script(&addr.0, Network::Bitcoin).map_err(|_| ())?;
  Ok(
    (match parsed_addr.address_type() {
      Some(AddressType::P2pkh) => {
        EncodedAddress::P2PKH(*parsed_addr.pubkey_hash().unwrap().as_raw_hash().as_byte_array())
      }
      Some(AddressType::P2sh) => {
        EncodedAddress::P2SH(*parsed_addr.script_hash().unwrap().as_raw_hash().as_byte_array())
      }
      Some(AddressType::P2wpkh) => {
        let program = parsed_addr.witness_program().ok_or(())?;
        let program = program.program().as_bytes();
        EncodedAddress::P2WPKH(program.try_into().map_err(|_| ())?)
      }
      Some(AddressType::P2wsh) => {
        let program = parsed_addr.witness_program().ok_or(())?;
        let program = program.program().as_bytes();
        EncodedAddress::P2WSH(program.try_into().map_err(|_| ())?)
      }
      Some(AddressType::P2tr) => {
        let program = parsed_addr.witness_program().ok_or(())?;
        let program = program.program().as_bytes();
        EncodedAddress::P2TR(program.try_into().map_err(|_| ())?)
      }
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

impl Address {
  pub fn new(address: ScriptBuf) -> Option<Self> {
    let res = Self(address);
    if try_to_vec(&res).is_ok() {
      return Some(res);
    }
    None
  }
}

use core::{str::FromStr, fmt};

use scale::{Encode, Decode};
use borsh::{BorshSerialize, BorshDeserialize};

use bitcoin::{
  hashes::{Hash as HashTrait, hash160::Hash},
  PubkeyHash, ScriptHash,
  network::Network,
  WitnessVersion, WitnessProgram, ScriptBuf,
  address::{AddressType, NetworkChecked, Address as BAddress},
};

use crate::primitives::ExternalAddress;

// SCALE-encodable representation of Bitcoin addresses, used internally.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, BorshSerialize, BorshDeserialize)]
enum EncodedAddress {
  P2PKH([u8; 20]),
  P2SH([u8; 20]),
  P2WPKH([u8; 20]),
  P2WSH([u8; 32]),
  P2TR([u8; 32]),
}

impl TryFrom<&ScriptBuf> for EncodedAddress {
  type Error = ();
  fn try_from(script_buf: &ScriptBuf) -> Result<Self, ()> {
    // This uses mainnet as our encodings don't specify a network.
    let parsed_addr =
      BAddress::<NetworkChecked>::from_script(script_buf, Network::Bitcoin).map_err(|_| ())?;
    Ok(match parsed_addr.address_type() {
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
  }
}

impl From<EncodedAddress> for ScriptBuf {
  fn from(encoded: EncodedAddress) -> Self {
    match encoded {
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
    }
  }
}

/// A Bitcoin address usable with Serai.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Address(ScriptBuf);

// Support consuming into the underlying ScriptBuf.
impl From<Address> for ScriptBuf {
  fn from(addr: Address) -> ScriptBuf {
    addr.0
  }
}

impl From<&Address> for BAddress {
  fn from(addr: &Address) -> BAddress {
    // This fails if the script doesn't have an address representation, yet all our representable
    // addresses' scripts do
    BAddress::<NetworkChecked>::from_script(&addr.0, Network::Bitcoin).unwrap()
  }
}

// Support converting a string into an address.
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

// Support converting an address into a string.
impl fmt::Display for Address {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    BAddress::from(self).fmt(f)
  }
}

impl TryFrom<ExternalAddress> for Address {
  type Error = ();
  fn try_from(data: ExternalAddress) -> Result<Address, ()> {
    // Decode as an EncodedAddress, then map to a ScriptBuf
    let mut data = data.as_ref();
    let encoded = EncodedAddress::decode(&mut data).map_err(|_| ())?;
    if !data.is_empty() {
      Err(())?
    }
    Ok(Address(ScriptBuf::from(encoded)))
  }
}

impl From<Address> for EncodedAddress {
  fn from(addr: Address) -> EncodedAddress {
    // Safe since only encodable addresses can be created
    EncodedAddress::try_from(&addr.0).unwrap()
  }
}

impl From<Address> for ExternalAddress {
  fn from(addr: Address) -> ExternalAddress {
    // Safe since all variants are fixed-length and fit into MAX_ADDRESS_LEN
    ExternalAddress::new(EncodedAddress::from(addr).encode()).unwrap()
  }
}

impl BorshSerialize for Address {
  fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
    EncodedAddress::from(self.clone()).serialize(writer)
  }
}

impl BorshDeserialize for Address {
  fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
    Ok(Self(ScriptBuf::from(EncodedAddress::deserialize_reader(reader)?)))
  }
}

impl Address {
  /// Create a new Address from a ScriptBuf.
  pub fn new(script_buf: ScriptBuf) -> Option<Self> {
    // If we can represent this Script, it's an acceptable address
    if EncodedAddress::try_from(&script_buf).is_ok() {
      return Some(Self(script_buf));
    }
    // Else, it isn't acceptable
    None
  }
}

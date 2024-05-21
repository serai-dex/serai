use core::{str::FromStr, fmt};

use scale::{Encode, Decode};

use bitcoin::{
  hashes::{Hash as HashTrait, hash160::Hash},
  PubkeyHash, ScriptHash,
  network::Network,
  WitnessVersion, WitnessProgram, ScriptBuf,
  address::{AddressType, NetworkChecked, Address as BAddressGeneric},
};

type BAddress = BAddressGeneric<NetworkChecked>;

#[derive(Clone, Eq, Debug)]
pub struct Address(BAddress);

impl PartialEq for Address {
  fn eq(&self, other: &Self) -> bool {
    // Since Serai defines the Bitcoin-address specification as a variant of the script alone,
    // define equivalency as the script alone
    self.0.script_pubkey() == other.0.script_pubkey()
  }
}

impl FromStr for Address {
  type Err = ();
  fn from_str(str: &str) -> Result<Address, ()> {
    Address::new(
      BAddressGeneric::from_str(str)
        .map_err(|_| ())?
        .require_network(Network::Bitcoin)
        .map_err(|_| ())?,
    )
    .ok_or(())
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
    Ok(Address(match EncodedAddress::decode(&mut data.as_ref()).map_err(|_| ())? {
      EncodedAddress::P2PKH(hash) => {
        BAddress::p2pkh(PubkeyHash::from_raw_hash(Hash::from_byte_array(hash)), Network::Bitcoin)
      }
      EncodedAddress::P2SH(hash) => {
        let script_hash = ScriptHash::from_raw_hash(Hash::from_byte_array(hash));
        let res =
          BAddress::from_script(&ScriptBuf::new_p2sh(&script_hash), Network::Bitcoin).unwrap();
        debug_assert_eq!(res.script_hash(), Some(script_hash));
        res
      }
      EncodedAddress::P2WPKH(hash) => BAddress::from_witness_program(
        WitnessProgram::new(WitnessVersion::V0, &hash).unwrap(),
        Network::Bitcoin,
      ),
      EncodedAddress::P2WSH(hash) => BAddress::from_witness_program(
        WitnessProgram::new(WitnessVersion::V0, &hash).unwrap(),
        Network::Bitcoin,
      ),
      EncodedAddress::P2TR(key) => BAddress::from_witness_program(
        WitnessProgram::new(WitnessVersion::V1, &key).unwrap(),
        Network::Bitcoin,
      ),
    }))
  }
}

fn try_to_vec(addr: &Address) -> Result<Vec<u8>, ()> {
  let witness_program = |addr: &Address| {
    let script = addr.0.script_pubkey();
    let program_push = script.as_script().instructions().last().ok_or(())?.map_err(|_| ())?;
    let program = program_push.push_bytes().ok_or(())?.as_bytes();
    Ok::<_, ()>(program.to_vec())
  };
  Ok(
    (match addr.0.address_type() {
      Some(AddressType::P2pkh) => {
        EncodedAddress::P2PKH(*addr.0.pubkey_hash().unwrap().as_raw_hash().as_byte_array())
      }
      Some(AddressType::P2sh) => {
        EncodedAddress::P2SH(*addr.0.script_hash().unwrap().as_raw_hash().as_byte_array())
      }
      Some(AddressType::P2wpkh) => {
        let program = witness_program(addr)?;
        let mut buf = [0; 20];
        buf.copy_from_slice(program.as_ref());
        EncodedAddress::P2WPKH(buf)
      }
      Some(AddressType::P2wsh) => {
        let program = witness_program(addr)?;
        let mut buf = [0; 32];
        buf.copy_from_slice(program.as_ref());
        EncodedAddress::P2WSH(buf)
      }
      Some(AddressType::P2tr) => {
        let program = witness_program(addr)?;
        let program_ref: &[u8] = program.as_ref();
        EncodedAddress::P2TR(program_ref.try_into().map_err(|_| ())?)
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

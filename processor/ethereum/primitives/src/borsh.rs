use ::borsh::{io, BorshSerialize, BorshDeserialize};

use alloy_primitives::{U256, Address};

/// Serialize a U256 with a borsh-compatible API.
pub fn serialize_u256(value: &U256, writer: &mut impl io::Write) -> io::Result<()> {
  let value: [u8; 32] = value.to_be_bytes();
  value.serialize(writer)
}

/// Deserialize an address with a borsh-compatible API.
pub fn deserialize_u256(reader: &mut impl io::Read) -> io::Result<U256> {
  <[u8; 32]>::deserialize_reader(reader).map(|value| U256::from_be_bytes(value))
}

/// Serialize an address with a borsh-compatible API.
pub fn serialize_address(address: &Address, writer: &mut impl io::Write) -> io::Result<()> {
  <[u8; 20]>::from(address.0).serialize(writer)
}

/// Deserialize an address with a borsh-compatible API.
pub fn deserialize_address(reader: &mut impl io::Read) -> io::Result<Address> {
  <[u8; 20]>::deserialize_reader(reader).map(|address| Address(address.into()))
}

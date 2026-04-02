use alloc::vec::Vec;

use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::balance::Amount;

/// The value of non-Bitcoin externals coins present at genesis, relative to Bitcoin.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct GenesisValues {
  /// The value of Ether, relative to Bitcoin.
  pub ether: Amount,
  /// The value of DAI, relative to Bitcoin.
  pub dai: Amount,
  /// The value of Monero, relative to Bitcoin.
  pub monero: Amount,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(GenesisValues);

impl GenesisValues {
  /// The message for the `Call::oraclize_values` signature.
  pub fn oraclize_values_message(&self) -> Vec<u8> {
    borsh::to_vec(&(b"GenesisLiquidity-oraclize_values", self)).unwrap()
  }
}

#[test]
fn serialize() {
  use rand_core::{RngCore as _, OsRng};

  let genesis_values = GenesisValues {
    ether: Amount(OsRng.next_u64()),
    dai: Amount(OsRng.next_u64()),
    monero: Amount(OsRng.next_u64()),
  };

  assert_eq!(
    GenesisValues::deserialize_reader(&mut borsh::to_vec(&genesis_values).unwrap().as_slice())
      .unwrap(),
    genesis_values
  );

  #[cfg(feature = "scale")]
  {
    use scale::{Encode as _, DecodeAll as _};
    assert_eq!(borsh::to_vec(&genesis_values).unwrap(), genesis_values.encode());
    assert_eq!(
      GenesisValues::decode_all(&mut genesis_values.encode().as_slice()).unwrap(),
      genesis_values
    );
  }
}

use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::{address::ExternalAddress, balance::ExternalBalance};

/// An instruction on how to transfer coins out.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub enum OutInstruction {
  /// Transfer to the specified address.
  Transfer(ExternalAddress),
}

/// An instruction on how to transfer coins out with the balance to use for the transfer out.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct OutInstructionWithBalance {
  /// The instruction on how to transfer coins out.
  pub instruction: OutInstruction,
  /// The balance to use for the transfer out.
  pub balance: ExternalBalance,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(OutInstructionWithBalance);

#[test]
fn serialize() {
  use alloc::vec;
  use rand_core::{RngCore as _, OsRng};

  use crate::{coin::ExternalCoin, balance::Amount};

  for coin in ExternalCoin::all() {
    #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
    let instruction = {
      let mut address = vec![0; ((OsRng.next_u64() as u32) % ExternalAddress::MAX_LEN) as usize];
      OsRng.fill_bytes(&mut address);
      OutInstruction::Transfer(ExternalAddress::try_from(address).unwrap())
    };
    let balance = ExternalBalance { coin, amount: Amount(OsRng.next_u64()) };
    let out_instruction_with_balance = OutInstructionWithBalance { instruction, balance };

    assert_eq!(
      OutInstructionWithBalance::deserialize_reader(
        &mut borsh::to_vec(&out_instruction_with_balance).unwrap().as_slice()
      )
      .unwrap(),
      out_instruction_with_balance
    );

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _};
      assert_eq!(
        borsh::to_vec(&out_instruction_with_balance).unwrap(),
        out_instruction_with_balance.encode()
      );
      assert_eq!(
        OutInstructionWithBalance::decode_all(
          &mut out_instruction_with_balance.encode().as_slice()
        )
        .unwrap(),
        out_instruction_with_balance
      );
    }
  }
}

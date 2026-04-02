use std::io;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  balance::ExternalBalance,
  instructions::{OutInstruction, OutInstructionWithBalance},
};

use crate::Address;

/// A payment to fulfill.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Payment<A: Address> {
  address: A,
  balance: ExternalBalance,
}

impl<A: Address> TryFrom<OutInstructionWithBalance> for Payment<A> {
  type Error = ();
  fn try_from(out_instruction_with_balance: OutInstructionWithBalance) -> Result<Self, ()> {
    Ok(match out_instruction_with_balance.instruction {
      OutInstruction::Transfer(address) => Payment {
        address: address.try_into().map_err(|_| ())?,
        balance: out_instruction_with_balance.balance,
      },
    })
  }
}

impl<A: Address> Payment<A> {
  /// Create a new Payment.
  pub fn new(address: A, balance: ExternalBalance) -> Self {
    Payment { address, balance }
  }

  /// The address to pay.
  pub fn address(&self) -> &A {
    &self.address
  }
  /// The balance to transfer.
  pub fn balance(&self) -> ExternalBalance {
    self.balance
  }

  /// Read a Payment.
  pub fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let address = A::deserialize_reader(reader)?;
    let balance = ExternalBalance::deserialize_reader(reader).map_err(io::Error::other)?;
    Ok(Self { address, balance })
  }
  /// Write the Payment.
  pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.address.serialize(writer)?;
    self.balance.serialize(writer)
  }
}

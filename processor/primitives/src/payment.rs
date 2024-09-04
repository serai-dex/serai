use std::io;

use scale::{Encode, Decode, IoReader};

use serai_primitives::{Balance, Data};
use serai_coins_primitives::OutInstructionWithBalance;

use crate::Address;

/// A payment to fulfill.
#[derive(Clone)]
pub struct Payment<A: Address> {
  address: A,
  balance: Balance,
  data: Option<Vec<u8>>,
}

impl<A: Address> TryFrom<OutInstructionWithBalance> for Payment<A> {
  type Error = ();
  fn try_from(out_instruction_with_balance: OutInstructionWithBalance) -> Result<Self, ()> {
    Ok(Payment {
      address: out_instruction_with_balance.instruction.address.try_into().map_err(|_| ())?,
      balance: out_instruction_with_balance.balance,
      data: out_instruction_with_balance.instruction.data.map(Data::consume),
    })
  }
}

impl<A: Address> Payment<A> {
  /// Create a new Payment.
  pub fn new(address: A, balance: Balance, data: Option<Vec<u8>>) -> Self {
    Payment { address, balance, data }
  }

  /// The address to pay.
  pub fn address(&self) -> &A {
    &self.address
  }
  /// The balance to transfer.
  pub fn balance(&self) -> Balance {
    self.balance
  }
  /// The data to associate with this payment.
  pub fn data(&self) -> &Option<Vec<u8>> {
    &self.data
  }

  /// Read a Payment.
  pub fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let address = A::read(reader)?;
    let reader = &mut IoReader(reader);
    let balance = Balance::decode(reader).map_err(io::Error::other)?;
    let data = Option::<Vec<u8>>::decode(reader).map_err(io::Error::other)?;
    Ok(Self { address, balance, data })
  }
  /// Write the Payment.
  pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.address.write(writer).unwrap();
    self.balance.encode_to(writer);
    self.data.encode_to(writer);
    Ok(())
  }
}

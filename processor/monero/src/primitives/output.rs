use std::io;

use ciphersuite::{
  group::{ff::PrimeField as _, GroupEncoding as _},
  WrappedGroup,
};
use dalek_ff_group::Ed25519;

use monero_wallet::WalletOutput;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  coin::ExternalCoin,
  balance::{Amount, ExternalBalance},
};
use serai_client_monero::Address;

use primitives::{OutputType, ReceivedOutput};

use crate::{EXTERNAL_SUBADDRESS, BRANCH_SUBADDRESS, CHANGE_SUBADDRESS, FORWARDED_SUBADDRESS};

#[derive(Clone, Copy, PartialEq, Eq, Default, Hash, Debug, BorshSerialize, BorshDeserialize)]
pub(crate) struct OutputId(pub(crate) [u8; 32]);
impl AsRef<[u8]> for OutputId {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}
impl AsMut<[u8]> for OutputId {
  fn as_mut(&mut self) -> &mut [u8] {
    self.0.as_mut()
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Output(pub(crate) WalletOutput);
impl ReceivedOutput<<Ed25519 as WrappedGroup>::G, Address> for Output {
  type Id = OutputId;
  type TransactionId = [u8; 32];

  fn kind(&self) -> OutputType {
    let subaddress = self.0.subaddress().unwrap();
    if subaddress == EXTERNAL_SUBADDRESS {
      return OutputType::External;
    }
    if subaddress == BRANCH_SUBADDRESS {
      return OutputType::Branch;
    }
    if subaddress == CHANGE_SUBADDRESS {
      return OutputType::Change;
    }
    if subaddress == FORWARDED_SUBADDRESS {
      return OutputType::Forwarded;
    }
    unreachable!("scanned output to unknown subaddress");
  }

  fn id(&self) -> Self::Id {
    OutputId(self.0.key().compress().to_bytes())
  }

  fn transaction_id(&self) -> Self::TransactionId {
    self.0.transaction()
  }

  fn key(&self) -> <Ed25519 as WrappedGroup>::G {
    // The spend key will be a key we generated, so it'll be in the prime-order subgroup
    // The output's key is the spend key + (key_offset * G), so it's in the prime-order subgroup if
    // the spend key is
    dalek_ff_group::EdwardsPoint::from_bytes(&self.0.key().compress().to_bytes()).unwrap() -
      dalek_ff_group::EdwardsPoint(
        *<Ed25519 as WrappedGroup>::generator() *
          dalek_ff_group::Scalar::from_repr(<[u8; 32]>::from(self.0.key_offset())).unwrap(),
      )
  }

  fn presumed_origin(&self) -> Option<Address> {
    None
  }

  fn balance(&self) -> ExternalBalance {
    ExternalBalance { coin: ExternalCoin::Monero, amount: Amount(self.0.commitment().amount) }
  }

  fn data(&self) -> &[u8] {
    self.0.arbitrary_data().first().map_or(&[], Vec::as_slice)
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.0.write(writer)
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    WalletOutput::read(reader).map(Self)
  }
}

use std::io;

use ciphersuite::{group::Group, Ciphersuite, Ed25519};

use monero_wallet::WalletOutput;

use scale::{Encode, Decode};
use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{
  primitives::{Coin, Amount, Balance},
  networks::monero::Address,
};

use primitives::{OutputType, ReceivedOutput};

#[rustfmt::skip]
#[derive(
  Clone, Copy, PartialEq, Eq, Default, Hash, Debug, Encode, Decode, BorshSerialize, BorshDeserialize,
)]
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
pub(crate) struct Output(WalletOutput);

impl Output {
  pub(crate) fn new(output: WalletOutput) -> Self {
    Self(output)
  }
}

impl ReceivedOutput<<Ed25519 as Ciphersuite>::G, Address> for Output {
  type Id = OutputId;
  type TransactionId = [u8; 32];

  fn kind(&self) -> OutputType {
    todo!("TODO")
  }

  fn id(&self) -> Self::Id {
    OutputId(self.0.key().compress().to_bytes())
  }

  fn transaction_id(&self) -> Self::TransactionId {
    self.0.transaction()
  }

  fn key(&self) -> <Ed25519 as Ciphersuite>::G {
    // The spend key will be a key we generated, so it'll be in the prime-order subgroup
    // The output's key is the spend key + (key_offset * G), so it's in the prime-order subgroup if
    // the spend key is
    dalek_ff_group::EdwardsPoint(
      self.0.key() - (*<Ed25519 as Ciphersuite>::G::generator() * self.0.key_offset()),
    )
  }

  fn presumed_origin(&self) -> Option<Address> {
    None
  }

  fn balance(&self) -> Balance {
    Balance { coin: Coin::Monero, amount: Amount(self.0.commitment().amount) }
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

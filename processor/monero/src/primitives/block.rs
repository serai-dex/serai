use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Ed25519};

use monero_wallet::{transaction::Transaction, block::Block as MBlock};

use serai_client::networks::monero::Address;

use primitives::{ReceivedOutput, EventualityTracker};

use crate::{output::Output, transaction::Eventuality};

#[derive(Clone, Debug)]
pub(crate) struct BlockHeader(pub(crate) MBlock);
impl primitives::BlockHeader for BlockHeader {
  fn id(&self) -> [u8; 32] {
    self.0.hash()
  }
  fn parent(&self) -> [u8; 32] {
    self.0.header.previous
  }
}

#[derive(Clone, Debug)]
pub(crate) struct Block(pub(crate) MBlock, Vec<Transaction>);

impl primitives::Block for Block {
  type Header = BlockHeader;

  type Key = <Ed25519 as Ciphersuite>::G;
  type Address = Address;
  type Output = Output;
  type Eventuality = Eventuality;

  fn id(&self) -> [u8; 32] {
    self.0.hash()
  }

  fn scan_for_outputs_unordered(&self, key: Self::Key) -> Vec<Self::Output> {
    todo!("TODO")
  }

  #[allow(clippy::type_complexity)]
  fn check_for_eventuality_resolutions(
    &self,
    eventualities: &mut EventualityTracker<Self::Eventuality>,
  ) -> HashMap<
    <Self::Output as ReceivedOutput<Self::Key, Self::Address>>::TransactionId,
    Self::Eventuality,
  > {
    todo!("TODO")
  }
}

use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Ed25519};

use monero_wallet::{transaction::Transaction, block::Block as MBlock, ViewPairError, GuaranteedViewPair, GuaranteedScanner};

use serai_client::networks::monero::Address;

use primitives::{ReceivedOutput, EventualityTracker};

use crate::{EXTERNAL_SUBADDRESS, BRANCH_SUBADDRESS, CHANGE_SUBADDRESS, FORWARDED_SUBADDRESS, output::Output, transaction::Eventuality};

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
    let view_pair = match GuaranteedViewPair::new(key.0, additional_key) {
      Ok(view_pair) => view_pair,
      Err(ViewPairError::TorsionedSpendKey) => unreachable!("dalek_ff_group::EdwardsPoint has torsion"),
  };
    let mut scanner = GuaranteedScanner::new(view_pair);
    scanner.register_subaddress(EXTERNAL_SUBADDRESS.unwrap());
    scanner.register_subaddress(BRANCH_SUBADDRESS.unwrap());
    scanner.register_subaddress(CHANGE_SUBADDRESS.unwrap());
    scanner.register_subaddress(FORWARDED_SUBADDRESS.unwrap());
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

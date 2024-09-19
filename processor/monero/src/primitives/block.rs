use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Ed25519};

use monero_wallet::{
  block::Block as MBlock, rpc::ScannableBlock as MScannableBlock, ScanError, GuaranteedScanner,
};

use serai_client::networks::monero::Address;

use primitives::{ReceivedOutput, EventualityTracker};
use crate::{
  EXTERNAL_SUBADDRESS, BRANCH_SUBADDRESS, CHANGE_SUBADDRESS, FORWARDED_SUBADDRESS, view_pair,
  output::Output, transaction::Eventuality,
};

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
pub(crate) struct Block(pub(crate) MScannableBlock);

impl primitives::Block for Block {
  type Header = BlockHeader;

  type Key = <Ed25519 as Ciphersuite>::G;
  type Address = Address;
  type Output = Output;
  type Eventuality = Eventuality;

  fn id(&self) -> [u8; 32] {
    self.0.block.hash()
  }

  fn scan_for_outputs_unordered(
    &self,
    _latest_active_key: Self::Key,
    key: Self::Key,
  ) -> Vec<Self::Output> {
    let mut scanner = GuaranteedScanner::new(view_pair(key));
    scanner.register_subaddress(EXTERNAL_SUBADDRESS);
    scanner.register_subaddress(BRANCH_SUBADDRESS);
    scanner.register_subaddress(CHANGE_SUBADDRESS);
    scanner.register_subaddress(FORWARDED_SUBADDRESS);
    match scanner.scan(self.0.clone()) {
      Ok(outputs) => outputs.not_additionally_locked().into_iter().map(Output).collect(),
      Err(ScanError::UnsupportedProtocol(version)) => {
        panic!("Monero unexpectedly hard-forked (version {version})")
      }
      Err(ScanError::InvalidScannableBlock(reason)) => {
        panic!("fetched an invalid scannable block from the RPC: {reason}")
      }
    }
  }

  #[allow(clippy::type_complexity)]
  fn check_for_eventuality_resolutions(
    &self,
    eventualities: &mut EventualityTracker<Self::Eventuality>,
  ) -> HashMap<
    <Self::Output as ReceivedOutput<Self::Key, Self::Address>>::TransactionId,
    Self::Eventuality,
  > {
    let mut res = HashMap::new();
    assert_eq!(self.0.block.transactions.len(), self.0.transactions.len());
    for (hash, tx) in self.0.block.transactions.iter().zip(&self.0.transactions) {
      if let Some(eventuality) = eventualities.active_eventualities.get(&tx.prefix().extra) {
        if eventuality.eventuality.matches(tx) {
          res.insert(*hash, eventualities.active_eventualities.remove(&tx.prefix().extra).unwrap());
        }
      }
    }
    res
  }
}

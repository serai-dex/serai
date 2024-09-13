use std::collections::HashMap;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ed25519};

use monero_wallet::{
  block::Block as MBlock, rpc::ScannableBlock as MScannableBlock, ViewPairError,
  GuaranteedViewPair, ScanError, GuaranteedScanner,
};

use serai_client::networks::monero::Address;

use primitives::{ReceivedOutput, EventualityTracker};
use view_keys::view_key;
use crate::{
  EXTERNAL_SUBADDRESS, BRANCH_SUBADDRESS, CHANGE_SUBADDRESS, FORWARDED_SUBADDRESS, output::Output,
  transaction::Eventuality,
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

  fn scan_for_outputs_unordered(&self, key: Self::Key) -> Vec<Self::Output> {
    let view_pair = match GuaranteedViewPair::new(key.0, Zeroizing::new(*view_key::<Ed25519>(0))) {
      Ok(view_pair) => view_pair,
      Err(ViewPairError::TorsionedSpendKey) => {
        unreachable!("dalek_ff_group::EdwardsPoint had torsion")
      }
    };
    let mut scanner = GuaranteedScanner::new(view_pair);
    scanner.register_subaddress(EXTERNAL_SUBADDRESS.unwrap());
    scanner.register_subaddress(BRANCH_SUBADDRESS.unwrap());
    scanner.register_subaddress(CHANGE_SUBADDRESS.unwrap());
    scanner.register_subaddress(FORWARDED_SUBADDRESS.unwrap());
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

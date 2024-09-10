use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Secp256k1};

use bitcoin_serai::bitcoin::block::{Header, Block as BBlock};

use serai_client::networks::bitcoin::Address;

use primitives::{ReceivedOutput, EventualityTracker};

use crate::{hash_bytes, scan::scanner, output::Output, transaction::Eventuality};

#[derive(Clone, Debug)]
pub(crate) struct BlockHeader(pub(crate) Header);
impl primitives::BlockHeader for BlockHeader {
  fn id(&self) -> [u8; 32] {
    hash_bytes(self.0.block_hash().to_raw_hash())
  }
  fn parent(&self) -> [u8; 32] {
    hash_bytes(self.0.prev_blockhash.to_raw_hash())
  }
}

#[derive(Clone, Debug)]
pub(crate) struct Block(pub(crate) BBlock);

#[async_trait::async_trait]
impl primitives::Block for Block {
  type Header = BlockHeader;

  type Key = <Secp256k1 as Ciphersuite>::G;
  type Address = Address;
  type Output = Output;
  type Eventuality = Eventuality;

  fn id(&self) -> [u8; 32] {
    primitives::BlockHeader::id(&BlockHeader(self.0.header))
  }

  fn scan_for_outputs_unordered(&self, key: Self::Key) -> Vec<Self::Output> {
    let scanner = scanner(key);

    let mut res = vec![];
    // We skip the coinbase transaction as its burdened by maturity
    for tx in &self.0.txdata[1 ..] {
      for output in scanner.scan_transaction(tx) {
        res.push(Output::new(key, tx, output));
      }
    }
    res
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
    for tx in &self.0.txdata[1 ..] {
      let id = hash_bytes(tx.compute_txid().to_raw_hash());
      if let Some(eventuality) = eventualities.active_eventualities.remove(id.as_slice()) {
        res.insert(id, eventuality);
      }
    }
    res
  }
}

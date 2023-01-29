use std::collections::HashMap;

use async_trait::async_trait;

use group::GroupEncoding;
use frost::curve::Ciphersuite;

use crate::{
  coin::{Block, Coin},
  scanner::{ChainNumber, ScannerDb},
};

pub(crate) struct ScannerMemDb {
  latest_scanned_block: HashMap<Vec<u8>, ChainNumber>,
  block: HashMap<ChainNumber, Vec<u8>>,
}

impl ScannerMemDb {
  pub(crate) fn new() -> ScannerMemDb {
    ScannerMemDb { latest_scanned_block: HashMap::new(), block: HashMap::new() }
  }
}

impl Default for ScannerMemDb {
  fn default() -> ScannerMemDb {
    ScannerMemDb::new()
  }
}

#[async_trait]
impl<C: Coin> ScannerDb<C> for ScannerMemDb {
  async fn get_latest_scanned_block(&self, key: <C::Curve as Ciphersuite>::G) -> ChainNumber {
    self
      .latest_scanned_block
      .get(&key.to_bytes().as_ref().to_vec())
      .cloned()
      .unwrap_or(ChainNumber(0))
  }

  async fn save_scanned_block(&mut self, key: <C::Curve as Ciphersuite>::G, block: ChainNumber) {
    self.latest_scanned_block.insert(key.to_bytes().as_ref().to_vec(), block);
  }

  async fn get_block(&self, number: ChainNumber) -> Option<<C::Block as Block>::Id> {
    self.block.get(&number).map(|bytes| {
      let mut id = <C::Block as Block>::Id::default();
      id.as_mut().copy_from_slice(bytes);
      id
    })
  }

  async fn save_block(&mut self, number: ChainNumber, id: <C::Block as Block>::Id) {
    self.block.insert(number, id.as_ref().to_vec());
  }
}

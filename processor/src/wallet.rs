use std::collections::HashMap;

use transcript::{Transcript, DigestTranscript};
use frost::{Curve, MultisigKeys};

use crate::{CoinError, Coin};

pub struct WalletKeys<C: Curve> {
  keys: MultisigKeys<C>,
  creation_height: usize
}

impl<C: Curve> WalletKeys<C> {
  pub fn new(keys: MultisigKeys<C>, creation_height: usize) -> WalletKeys<C> {
    WalletKeys { keys, creation_height }
  }

  // Bind this key to a specific network by applying an additive offset
  // While it would be fine to just C::id(), including the group key creates distinct
  // offsets instead of static offsets. Under a statically offset system, a BTC key could
  // have X subtracted to find the potential group key, and then have Y added to find the
  // potential ETH group key. While this shouldn't be an issue, as this isn't a private
  // system, there are potentially other benefits to binding this to a specific group key
  // It's no longer possible to influence group key gen to key cancel without breaking the hash
  // function as well, although that degree of influence means key gen is broken already
  fn bind(&self, chain: &[u8]) -> MultisigKeys<C> {
    const DST: &[u8] = b"Serai Processor Wallet Chain Bind";
    let mut transcript = DigestTranscript::<blake2::Blake2b512>::new(DST);
    transcript.append_message(b"chain", chain);
    transcript.append_message(b"curve", C::id());
    transcript.append_message(b"group_key", &C::G_to_bytes(&self.keys.group_key()));
    self.keys.offset(C::hash_to_F(DST, &transcript.challenge(b"offset")))
  }
}

pub struct CoinDb {
  // Height this coin has been scanned to
  scanned_height: usize,
  // Acknowledged height for a given canonical height
  acknowledged_heights: HashMap<usize, usize>
}

pub struct Wallet<C: Coin> {
  db: CoinDb,
  coin: C,
  keys: Vec<MultisigKeys<C::Curve>>,
  pending: Vec<(usize, MultisigKeys<C::Curve>)>,
  outputs: Vec<C::Output>
}

impl<C: Coin> Wallet<C> {
  pub fn new(coin: C) -> Wallet<C> {
    Wallet {
      db: CoinDb {
        scanned_height: 0,
        acknowledged_heights: HashMap::new(),
      },

      coin,

      keys: vec![],
      pending: vec![],
      outputs: vec![]
    }
  }

  pub fn scanned_height(&self) -> usize { self.db.scanned_height }
  pub fn acknowledge_height(&mut self, canonical: usize, height: usize) {
    debug_assert!(!self.db.acknowledged_heights.contains_key(&canonical));
    self.db.acknowledged_heights.insert(canonical, height);
  }
  pub fn acknowledged_height(&self, canonical: usize) -> usize {
    self.db.acknowledged_heights[&canonical]
  }

  pub fn add_keys(&mut self, keys: &WalletKeys<C::Curve>) {
    // Doesn't use +1 as this is height, not block index, and poll moves by block index
    self.pending.push((self.acknowledged_height(keys.creation_height), keys.bind(C::id())));
  }

  pub async fn poll(&mut self) -> Result<(), CoinError> {
    let confirmed_height = self.coin.get_height().await? - C::confirmations();
    for h in self.scanned_height() .. confirmed_height {
      let mut k = 0;
      while k < self.pending.len() {
        if h == self.pending[k].0 {
          self.keys.push(self.pending.swap_remove(k).1);
        } else {
          k += 1;
        }
      }

      let block = self.coin.get_block(h).await?;
      for keys in &self.keys {
        let outputs = self.coin.get_outputs(&block, keys.group_key());
      }
    }
    Ok(())
  }
}

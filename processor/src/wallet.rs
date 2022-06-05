use std::{sync::Arc, collections::HashMap};

use transcript::{Transcript, DigestTranscript};
use frost::{Curve, MultisigKeys};

use crate::{CoinError, Output, Coin};

pub struct WalletKeys<C: Curve> {
  keys: MultisigKeys<C>,
  creation_height: usize
}

impl<C: Curve> WalletKeys<C> {
  pub fn new(keys: MultisigKeys<C>, creation_height: usize) -> WalletKeys<C> {
    WalletKeys { keys, creation_height }
  }

  // Bind this key to a specific network by applying an additive offset
  // While it would be fine to just C::ID, including the group key creates distinct
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
    transcript.append_message(b"curve", C::ID);
    transcript.append_message(b"group_key", &C::G_to_bytes(&self.keys.group_key()));
    self.keys.offset(C::hash_to_F(DST, &transcript.challenge(b"offset")))
  }
}

pub trait CoinDb {
  // Set a height as scanned to
  fn scanned_to_height(&mut self, height: usize);
  // Acknowledge a given coin height for a canonical height
  fn acknowledge_height(&mut self, canonical: usize, height: usize);

  // Adds an output to the DB. Returns false if the output was already added
  fn add_output<O: Output>(&mut self, output: &O) -> bool;

  // Height this coin has been scanned to
  fn scanned_height(&self) -> usize;
  // Acknowledged height for a given canonical height
  fn acknowledged_height(&self, canonical: usize) -> usize;
}

pub struct MemCoinDb {
  // Height this coin has been scanned to
  scanned_height: usize,
  // Acknowledged height for a given canonical height
  acknowledged_heights: HashMap<usize, usize>,
  outputs: HashMap<Vec<u8>, Vec<u8>>
}


impl MemCoinDb {
  pub fn new() -> MemCoinDb {
    MemCoinDb {
      scanned_height: 0,
      acknowledged_heights: HashMap::new(),
      outputs: HashMap::new()
    }
  }
}

impl CoinDb for MemCoinDb {
  fn scanned_to_height(&mut self, height: usize) {
    self.scanned_height = height;
  }

  fn acknowledge_height(&mut self, canonical: usize, height: usize) {
    debug_assert!(!self.acknowledged_heights.contains_key(&canonical));
    self.acknowledged_heights.insert(canonical, height);
  }

  fn add_output<O: Output>(&mut self, output: &O) -> bool {
    // This would be insecure as we're indexing by ID and this will replace the output as a whole
    // Multiple outputs may have the same ID in edge cases such as Monero, where outputs are ID'd
    // by key image, not by hash + index
    // self.outputs.insert(output.id(), output).is_some()
    let id = output.id().as_ref().to_vec();
    if self.outputs.contains_key(&id) {
      return false;
    }
    self.outputs.insert(id, output.serialize());
    true
  }

  fn scanned_height(&self) -> usize {
    self.scanned_height
  }

  fn acknowledged_height(&self, canonical: usize) -> usize {
    self.acknowledged_heights[&canonical]
  }
}

pub struct Wallet<D: CoinDb, C: Coin> {
  db: D,
  coin: C,
  keys: Vec<(Arc<MultisigKeys<C::Curve>>, Vec<C::Output>)>,
  pending: Vec<(usize, MultisigKeys<C::Curve>)>
}

impl<D: CoinDb, C: Coin> Wallet<D, C> {
  pub fn new(db: D, coin: C) -> Wallet<D, C> {
    Wallet {
      db,
      coin,

      keys: vec![],
      pending: vec![]
    }
  }

  pub fn scanned_height(&self) -> usize { self.db.scanned_height() }
  pub fn acknowledge_height(&mut self, canonical: usize, height: usize) {
    self.db.acknowledge_height(canonical, height);
  }
  pub fn acknowledged_height(&self, canonical: usize) -> usize {
    self.db.acknowledged_height(canonical)
  }

  pub fn add_keys(&mut self, keys: &WalletKeys<C::Curve>) {
    // Doesn't use +1 as this is height, not block index, and poll moves by block index
    self.pending.push((self.acknowledged_height(keys.creation_height), keys.bind(C::ID)));
  }

  pub async fn poll(&mut self) -> Result<(), CoinError> {
    let confirmed_height = self.coin.get_height().await? - C::CONFIRMATIONS;
    for height in self.scanned_height() .. confirmed_height {
      // If any keys activated at this height, shift them over
      {
        let mut k = 0;
        while k < self.pending.len() {
          // TODO
          //if height < self.pending[k].0 {
          //} else if height == self.pending[k].0 {
          if height <= self.pending[k].0 {
            self.keys.push((Arc::new(self.pending.swap_remove(k).1), vec![]));
          } else {
            k += 1;
          }
        }
      }

      let block = self.coin.get_block(height).await?;
      for (keys, outputs) in self.keys.iter_mut() {
        outputs.extend(
          self.coin.get_outputs(&block, keys.group_key()).await.iter().cloned().filter(
            |output| self.db.add_output(output)
          )
        );
      }
    }
    Ok(())
  }

  // This should be called whenever new outputs are received, meaning there was a new block
  // If these outputs were received and sent to Substrate, it should be called after they're
  // included in a block and we have results to act on
  // If these outputs weren't sent to Substrate (change), it should be called immediately
  // with all payments still queued from the last call
  pub async fn prepare_sends(
    &mut self,
    canonical: usize,
    payments: Vec<(C::Address, u64)>
  ) -> Result<(Vec<(C::Address, u64)>, Vec<C::SignableTransaction>), CoinError> {
    if payments.len() == 0 {
      return Ok((vec![], vec![]));
    }

    let acknowledged_height = self.acknowledged_height(canonical);

    // TODO: Log schedule outputs when MAX_OUTPUTS is lower than payments.len()
    // Payments is the first set of TXs in the schedule
    // As each payment re-appears, let mut payments = schedule[payment] where the only input is
    // the source payment
    // let (mut payments, schedule) = payments;
    let mut payments = payments;
    payments.sort_by(|a, b| a.1.cmp(&b.1).reverse());

    let mut txs = vec![];
    for (keys, outputs) in self.keys.iter_mut() {
      // Select the highest value outputs to minimize the amount of inputs needed
      outputs.sort_by(|a, b| a.amount().cmp(&b.amount()).reverse());

      while outputs.len() != 0 {
        // Select the maximum amount of outputs possible
        let mut inputs = &outputs[0 .. C::MAX_INPUTS.min(outputs.len())];

        // Calculate their sum value, minus the fee needed to spend them
        let mut sum = inputs.iter().map(|input| input.amount()).sum::<u64>();
        // sum -= C::MAX_FEE; // TODO

        // Grab the payments this will successfully fund
        let mut these_payments = vec![];
        for payment in &payments {
          if sum > payment.1 {
            these_payments.push(payment);
            sum -= payment.1;
          }
          // Doesn't break in this else case as a smaller payment may still fit
        }

        // Move to the next set of keys if none of these outputs remain significant
        if these_payments.len() == 0 {
          break;
        }

        // Drop any uneeded outputs
        while sum > inputs[inputs.len() - 1].amount() {
          sum -= inputs[inputs.len() - 1].amount();
          inputs = &inputs[.. (inputs.len() - 1)];
        }

        // We now have a minimal effective outputs/payments set
        // Take ownership while removing these candidates from the provided list
        let inputs = outputs.drain(.. inputs.len()).collect();
        let payments = payments.drain(.. these_payments.len()).collect::<Vec<_>>();

        let tx = self.coin.prepare_send(
          keys.clone(),
          format!(
            "Serai Processor Wallet Send (height {}, index {})",
            canonical,
            txs.len()
          ).as_bytes().to_vec(),
          acknowledged_height,
          inputs,
          &payments
        ).await?;
        // self.db.save_tx(tx) // TODO
        txs.push(tx);
      }
    }

    Ok((payments, txs))
  }
}

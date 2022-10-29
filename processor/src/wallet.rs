use std::collections::HashMap;

use rand_core::OsRng;

use group::GroupEncoding;

use transcript::{Transcript, RecommendedTranscript};
use frost::{
  curve::Curve,
  FrostError, FrostKeys,
  sign::{Writable, PreprocessMachine, SignMachine, SignatureMachine},
};

use crate::{
  coin::{CoinError, Output, Coin},
  SignError, Network,
};

pub struct WalletKeys<C: Curve> {
  keys: FrostKeys<C>,
  creation_block: usize,
}

impl<C: Curve> WalletKeys<C> {
  pub fn new(keys: FrostKeys<C>, creation_block: usize) -> WalletKeys<C> {
    WalletKeys { keys, creation_block }
  }

  // Bind this key to a specific network by applying an additive offset
  // While it would be fine to just C::ID, including the group key creates distinct
  // offsets instead of static offsets. Under a statically offset system, a BTC key could
  // have X subtracted to find the potential group key, and then have Y added to find the
  // potential ETH group key. While this shouldn't be an issue, as this isn't a private
  // system, there are potentially other benefits to binding this to a specific group key
  // It's no longer possible to influence group key gen to key cancel without breaking the hash
  // function as well, although that degree of influence means key gen is broken already
  fn bind(&self, chain: &[u8]) -> FrostKeys<C> {
    const DST: &[u8] = b"Serai Processor Wallet Chain Bind";
    let mut transcript = RecommendedTranscript::new(DST);
    transcript.append_message(b"chain", chain);
    transcript.append_message(b"curve", C::ID);
    transcript.append_message(b"group_key", self.keys.group_key().to_bytes().as_ref());
    self.keys.offset(C::hash_to_F(DST, &transcript.challenge(b"offset")))
  }
}

pub trait CoinDb {
  // Set a block as scanned to
  fn scanned_to_block(&mut self, block: usize);
  // Acknowledge a specific block number as part of a canonical block
  fn acknowledge_block(&mut self, canonical: usize, block: usize);

  // Adds an output to the DB. Returns false if the output was already added
  fn add_output<O: Output>(&mut self, output: &O) -> bool;

  // Block this coin has been scanned to (inclusive)
  fn scanned_block(&self) -> usize;
  // Acknowledged block for a given canonical block
  fn acknowledged_block(&self, canonical: usize) -> usize;
}

pub struct MemCoinDb {
  // Height this coin has been scanned to
  scanned_block: usize,
  // Acknowledged block for a given canonical block
  acknowledged_blocks: HashMap<usize, usize>,
  outputs: HashMap<Vec<u8>, Vec<u8>>,
}

impl MemCoinDb {
  pub fn new() -> MemCoinDb {
    MemCoinDb { scanned_block: 0, acknowledged_blocks: HashMap::new(), outputs: HashMap::new() }
  }
}

impl CoinDb for MemCoinDb {
  fn scanned_to_block(&mut self, block: usize) {
    self.scanned_block = block;
  }

  fn acknowledge_block(&mut self, canonical: usize, block: usize) {
    debug_assert!(!self.acknowledged_blocks.contains_key(&canonical));
    self.acknowledged_blocks.insert(canonical, block);
  }

  fn add_output<O: Output>(&mut self, output: &O) -> bool {
    // This would be insecure as we're indexing by ID and this will replace the output as a whole
    // Multiple outputs may have the same ID in edge cases such as Monero, where outputs are ID'd
    // by output key, not by hash + index
    // self.outputs.insert(output.id(), output).is_some()
    let id = output.id().as_ref().to_vec();
    if self.outputs.contains_key(&id) {
      return false;
    }
    self.outputs.insert(id, output.serialize());
    true
  }

  fn scanned_block(&self) -> usize {
    self.scanned_block
  }

  fn acknowledged_block(&self, canonical: usize) -> usize {
    self.acknowledged_blocks[&canonical]
  }
}

fn select_inputs<C: Coin>(inputs: &mut Vec<C::Output>) -> (Vec<C::Output>, u64) {
  // Sort to ensure determinism. Inefficient, yet produces the most legible code to be optimized
  // later
  inputs.sort_by_key(|a| a.amount());

  // Select the maximum amount of outputs possible
  let res = inputs.split_off(inputs.len() - C::MAX_INPUTS.min(inputs.len()));
  // Calculate their sum value, minus the fee needed to spend them
  let sum = res.iter().map(|input| input.amount()).sum();
  // sum -= C::MAX_FEE; // TODO
  (res, sum)
}

fn select_outputs<C: Coin>(
  payments: &mut Vec<(C::Address, u64)>,
  value: &mut u64,
) -> Vec<(C::Address, u64)> {
  // Prioritize large payments which will most efficiently use large inputs
  payments.sort_by(|a, b| a.1.cmp(&b.1));

  // Grab the payments this will successfully fund
  let mut outputs = vec![];
  let mut p = payments.len();
  while p != 0 {
    p -= 1;
    if *value >= payments[p].1 {
      *value -= payments[p].1;
      // Swap remove will either pop the tail or insert an element that wouldn't fit, making it
      // always safe to move past
      outputs.push(payments.swap_remove(p));
    }
    // Doesn't break in this else case as a smaller payment may still fit
  }

  outputs
}

// Optimizes on the expectation selected/inputs are sorted from lowest value to highest
fn refine_inputs<C: Coin>(
  selected: &mut Vec<C::Output>,
  inputs: &mut Vec<C::Output>,
  mut remaining: u64,
) {
  // Drop unused inputs
  let mut s = 0;
  while remaining > selected[s].amount() {
    remaining -= selected[s].amount();
    s += 1;
  }
  // Add them back to the inputs pool
  inputs.extend(selected.drain(.. s));

  // Replace large inputs with smaller ones
  for s in (0 .. selected.len()).rev() {
    for input in inputs.iter_mut() {
      // Doesn't break due to inputs no longer being sorted
      // This could be made faster if we prioritized small input usage over transaction size/fees
      // TODO: Consider. This would implicitly consolidate inputs which would be advantageous
      if selected[s].amount() < input.amount() {
        continue;
      }

      // If we can successfully replace this input, do so
      let diff = selected[s].amount() - input.amount();
      if remaining > diff {
        remaining -= diff;

        let old = selected[s].clone();
        selected[s] = input.clone();
        *input = old;
      }
    }
  }
}

fn select_inputs_outputs<C: Coin>(
  inputs: &mut Vec<C::Output>,
  outputs: &mut Vec<(C::Address, u64)>,
) -> (Vec<C::Output>, Vec<(C::Address, u64)>) {
  if inputs.is_empty() {
    return (vec![], vec![]);
  }

  let (mut selected, mut value) = select_inputs::<C>(inputs);

  let outputs = select_outputs::<C>(outputs, &mut value);
  if outputs.is_empty() {
    inputs.extend(selected);
    return (vec![], vec![]);
  }

  refine_inputs::<C>(&mut selected, inputs, value);
  (selected, outputs)
}

pub struct Wallet<D: CoinDb, C: Coin> {
  db: D,
  coin: C,
  keys: Vec<(FrostKeys<C::Curve>, Vec<C::Output>)>,
  pending: Vec<(usize, FrostKeys<C::Curve>)>,
}

impl<D: CoinDb, C: Coin> Wallet<D, C> {
  pub fn new(db: D, coin: C) -> Wallet<D, C> {
    Wallet { db, coin, keys: vec![], pending: vec![] }
  }

  pub fn scanned_block(&self) -> usize {
    self.db.scanned_block()
  }
  pub fn acknowledge_block(&mut self, canonical: usize, block: usize) {
    self.db.acknowledge_block(canonical, block);
  }
  pub fn acknowledged_block(&self, canonical: usize) -> usize {
    self.db.acknowledged_block(canonical)
  }

  pub fn add_keys(&mut self, keys: &WalletKeys<C::Curve>) {
    self.pending.push((self.acknowledged_block(keys.creation_block), keys.bind(C::ID)));
  }

  pub fn address(&self) -> C::Address {
    self.coin.address(self.keys[self.keys.len() - 1].0.group_key())
  }

  // TODO: Remove
  pub async fn is_confirmed(&mut self, tx: &[u8]) -> Result<bool, CoinError> {
    self.coin.is_confirmed(tx).await
  }

  pub async fn poll(&mut self) -> Result<(), CoinError> {
    if self.coin.get_latest_block_number().await? < (C::CONFIRMATIONS - 1) {
      return Ok(());
    }
    let confirmed_block = self.coin.get_latest_block_number().await? - (C::CONFIRMATIONS - 1);

    // Will never scan the genesis block, which shouldn't be an issue
    for b in (self.scanned_block() + 1) ..= confirmed_block {
      // If any keys activated at this block, shift them over
      {
        let mut k = 0;
        while k < self.pending.len() {
          // TODO
          //if b < self.pending[k].0 {
          //} else if b == self.pending[k].0 {
          if b <= self.pending[k].0 {
            self.keys.push((self.pending.swap_remove(k).1, vec![]));
          } else {
            k += 1;
          }
        }
      }

      let block = self.coin.get_block(b).await?;
      for (keys, outputs) in self.keys.iter_mut() {
        outputs.extend(
          self
            .coin
            .get_outputs(&block, keys.group_key())
            .await?
            .iter()
            .cloned()
            .filter(|output| self.db.add_output(output)),
        );
      }

      self.db.scanned_to_block(b);
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
    payments: Vec<(C::Address, u64)>,
    fee: C::Fee,
  ) -> Result<(Vec<(C::Address, u64)>, Vec<C::SignableTransaction>), CoinError> {
    if payments.is_empty() {
      return Ok((vec![], vec![]));
    }

    let acknowledged_block = self.acknowledged_block(canonical);

    // TODO: Log schedule outputs when MAX_OUTPUTS is lower than payments.len()
    // Payments is the first set of TXs in the schedule
    // As each payment re-appears, let mut payments = schedule[payment] where the only input is
    // the source payment
    // let (mut payments, schedule) = schedule(payments);
    let mut payments = payments;

    let mut txs = vec![];
    for (keys, outputs) in self.keys.iter_mut() {
      while !outputs.is_empty() {
        let (inputs, outputs) = select_inputs_outputs::<C>(outputs, &mut payments);
        // If we can no longer process any payments, move to the next set of keys
        if outputs.is_empty() {
          debug_assert_eq!(inputs.len(), 0);
          break;
        }

        // Create the transcript for this transaction
        let mut transcript = RecommendedTranscript::new(b"Serai Processor Wallet Send");
        transcript
          .append_message(b"canonical_block", &u64::try_from(canonical).unwrap().to_le_bytes());
        transcript.append_message(
          b"acknowledged_block",
          &u64::try_from(acknowledged_block).unwrap().to_le_bytes(),
        );
        transcript.append_message(b"index", &u64::try_from(txs.len()).unwrap().to_le_bytes());

        let tx = self
          .coin
          .prepare_send(keys.clone(), transcript, acknowledged_block, inputs, &outputs, fee)
          .await?;
        // self.db.save_tx(tx) // TODO
        txs.push(tx);
      }
    }

    Ok((payments, txs))
  }

  pub async fn attempt_send<N: Network>(
    &mut self,
    network: &mut N,
    prepared: C::SignableTransaction,
    included: Vec<u16>,
  ) -> Result<(Vec<u8>, Vec<<C::Output as Output>::Id>), SignError> {
    let attempt =
      self.coin.attempt_send(prepared, &included).await.map_err(SignError::CoinError)?;

    let (attempt, commitments) = attempt.preprocess(&mut OsRng);
    let commitments = network
      .round(commitments.serialize())
      .await
      .map_err(SignError::NetworkError)?
      .drain()
      .map(|(validator, preprocess)| {
        Ok((
          validator,
          attempt
            .read_preprocess::<&[u8]>(&mut preprocess.as_ref())
            .map_err(|_| SignError::FrostError(FrostError::InvalidPreprocess(validator)))?,
        ))
      })
      .collect::<Result<HashMap<_, _>, _>>()?;

    let (attempt, share) = attempt.sign(commitments, b"").map_err(SignError::FrostError)?;
    let shares = network
      .round(share.serialize())
      .await
      .map_err(SignError::NetworkError)?
      .drain()
      .map(|(validator, share)| {
        Ok((
          validator,
          attempt
            .read_share::<&[u8]>(&mut share.as_ref())
            .map_err(|_| SignError::FrostError(FrostError::InvalidShare(validator)))?,
        ))
      })
      .collect::<Result<HashMap<_, _>, _>>()?;

    let tx = attempt.complete(shares).map_err(SignError::FrostError)?;

    self.coin.publish_transaction(&tx).await.map_err(SignError::CoinError)
  }
}

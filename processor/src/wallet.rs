use std::{collections::HashMap, sync::Arc};

use rand_core::OsRng;

use group::GroupEncoding;

use frost::{
    curve::Curve,
    sign::{PreprocessMachine, SignMachine, SignatureMachine},
    FrostKeys,
};
use transcript::{RecommendedTranscript, Transcript};

use crate::{
    coin::{Coin, CoinError, Output},
    Network, SignError,
};

pub struct WalletKeys<C: Curve> {
    keys: FrostKeys<C>,
    creation_height: usize,
}

impl<C: Curve> WalletKeys<C> {
    pub fn new(keys: FrostKeys<C>, creation_height: usize) -> WalletKeys<C> {
        WalletKeys {
            keys,
            creation_height,
        }
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
        self.keys
            .offset(C::hash_to_F(DST, &transcript.challenge(b"offset")))
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
    outputs: HashMap<Vec<u8>, Vec<u8>>,
}

impl MemCoinDb {
    pub fn new() -> MemCoinDb {
        MemCoinDb {
            scanned_height: 0,
            acknowledged_heights: HashMap::new(),
            outputs: HashMap::new(),
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

fn select_inputs<C: Coin>(inputs: &mut Vec<C::Output>) -> (Vec<C::Output>, u64) {
    // Sort to ensure determinism. Inefficient, yet produces the most legible code to be optimized
    // later
    inputs.sort_by(|a, b| a.amount().cmp(&b.amount()));

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
    inputs.extend(selected.drain(..s));

    // Replace large inputs with smaller ones
    for s in (0..selected.len()).rev() {
        for i in 0..inputs.len() {
            // Doesn't break due to inputs no longer being sorted
            // This could be made faster if we prioritized small input usage over transaction size/fees
            // TODO: Consider. This would implicitly consolidate inputs which would be advantageous
            if selected[s].amount() < inputs[i].amount() {
                continue;
            }

            // If we can successfully replace this input, do so
            let diff = selected[s].amount() - inputs[i].amount();
            if remaining > diff {
                remaining -= diff;

                let old = selected[s].clone();
                selected[s] = inputs[i].clone();
                inputs[i] = old;
            }
        }
    }
}

fn select_inputs_outputs<C: Coin>(
    inputs: &mut Vec<C::Output>,
    outputs: &mut Vec<(C::Address, u64)>,
) -> (Vec<C::Output>, Vec<(C::Address, u64)>) {
    if inputs.len() == 0 {
        return (vec![], vec![]);
    }

    let (mut selected, mut value) = select_inputs::<C>(inputs);

    let outputs = select_outputs::<C>(outputs, &mut value);
    if outputs.len() == 0 {
        inputs.extend(selected);
        return (vec![], vec![]);
    }

    refine_inputs::<C>(&mut selected, inputs, value);
    (selected, outputs)
}

pub struct Wallet<D: CoinDb, C: Coin> {
    db: D,
    coin: C,
    keys: Vec<(Arc<FrostKeys<C::Curve>>, Vec<C::Output>)>,
    pending: Vec<(usize, FrostKeys<C::Curve>)>,
}

impl<D: CoinDb, C: Coin> Wallet<D, C> {
    pub fn new(db: D, coin: C) -> Wallet<D, C> {
        Wallet {
            db,
            coin,

            keys: vec![],
            pending: vec![],
        }
    }

    pub fn scanned_height(&self) -> usize {
        self.db.scanned_height()
    }
    pub fn acknowledge_height(&mut self, canonical: usize, height: usize) {
        self.db.acknowledge_height(canonical, height);
        if height > self.db.scanned_height() {
            self.db.scanned_to_height(height);
        }
    }
    pub fn acknowledged_height(&self, canonical: usize) -> usize {
        self.db.acknowledged_height(canonical)
    }

    pub fn add_keys(&mut self, keys: &WalletKeys<C::Curve>) {
        // Doesn't use +1 as this is height, not block index, and poll moves by block index
        self.pending.push((
            self.acknowledged_height(keys.creation_height),
            keys.bind(C::ID),
        ));
    }

    pub fn address(&self) -> C::Address {
        self.coin
            .address(self.keys[self.keys.len() - 1].0.group_key())
    }

    pub async fn poll(&mut self) -> Result<(), CoinError> {
        if self.coin.get_height().await? < C::CONFIRMATIONS {
            return Ok(());
        }
        let confirmed_block = self.coin.get_height().await? - C::CONFIRMATIONS;

        for b in self.scanned_height()..=confirmed_block {
            // If any keys activated at this height, shift them over
            {
                let mut k = 0;
                while k < self.pending.len() {
                    // TODO
                    //if b < self.pending[k].0 {
                    //} else if b == self.pending[k].0 {
                    if b <= self.pending[k].0 {
                        self.keys
                            .push((Arc::new(self.pending.swap_remove(k).1), vec![]));
                    } else {
                        k += 1;
                    }
                }
            }

            let block = self.coin.get_block(b).await?;
            for (keys, outputs) in self.keys.iter_mut() {
                outputs.extend(
                    self.coin
                        .get_outputs(&block, keys.group_key())
                        .await
                        .iter()
                        .cloned()
                        .filter(|output| self.db.add_output(output)),
                );
            }

            // Blocks are zero-indexed while heights aren't
            self.db.scanned_to_height(b + 1);
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
        if payments.len() == 0 {
            return Ok((vec![], vec![]));
        }

        let acknowledged_height = self.acknowledged_height(canonical);

        // TODO: Log schedule outputs when MAX_OUTPUTS is lower than payments.len()
        // Payments is the first set of TXs in the schedule
        // As each payment re-appears, let mut payments = schedule[payment] where the only input is
        // the source payment
        // let (mut payments, schedule) = schedule(payments);
        let mut payments = payments;

        let mut txs = vec![];
        for (keys, outputs) in self.keys.iter_mut() {
            while outputs.len() != 0 {
                let (inputs, outputs) = select_inputs_outputs::<C>(outputs, &mut payments);
                // If we can no longer process any payments, move to the next set of keys
                if outputs.len() == 0 {
                    debug_assert_eq!(inputs.len(), 0);
                    break;
                }

                // Create the transcript for this transaction
                let mut transcript = RecommendedTranscript::new(b"Serai Processor Wallet Send");
                transcript.append_message(
                    b"canonical_height",
                    &u64::try_from(canonical).unwrap().to_le_bytes(),
                );
                transcript.append_message(
                    b"acknowledged_height",
                    &u64::try_from(acknowledged_height).unwrap().to_le_bytes(),
                );
                transcript
                    .append_message(b"index", &u64::try_from(txs.len()).unwrap().to_le_bytes());

                let tx = self
                    .coin
                    .prepare_send(
                        keys.clone(),
                        transcript,
                        acknowledged_height,
                        inputs,
                        &outputs,
                        fee,
                    )
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
        let attempt = self
            .coin
            .attempt_send(prepared, &included)
            .await
            .map_err(|e| SignError::CoinError(e))?;

        let (attempt, commitments) = attempt.preprocess(&mut OsRng);
        let commitments = network
            .round(commitments)
            .await
            .map_err(|e| SignError::NetworkError(e))?;

        let (attempt, share) = attempt
            .sign(commitments, b"")
            .map_err(|e| SignError::FrostError(e))?;
        let shares = network
            .round(share)
            .await
            .map_err(|e| SignError::NetworkError(e))?;

        let tx = attempt
            .complete(shares)
            .map_err(|e| SignError::FrostError(e))?;

        self.coin
            .publish_transaction(&tx)
            .await
            .map_err(|e| SignError::CoinError(e))
    }
}

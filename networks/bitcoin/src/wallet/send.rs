use std_shims::{
  prelude::*,
  io::{self, Read},
  collections::HashMap,
};

use thiserror::Error;

use rand_core::{RngCore, CryptoRng};

use k256::Scalar;
use frost::{curve::Secp256k1, Participant, ThresholdKeys, FrostError, sign::*};

use bitcoin::{
  hashes::Hash as _,
  sighash::{TapSighashType, SighashCache, Prevouts},
  absolute::LockTime,
  script::{PushBytesBuf, ScriptBuf},
  transaction::{Version, Transaction},
  OutPoint, Sequence, Witness, TxIn, Amount, TxOut,
};

use crate::{crypto::Schnorr, wallet::ReceivedOutput};

#[rustfmt::skip]
// https://github.com/bitcoin/bitcoin/blob/306ccd4927a2efe325c8d84be1bdb79edeb29b04/src/policy/policy.cpp#L26-L63
// As the above notes, a lower amount may not be considered dust if contained in a SegWit output
// This doesn't bother with delineation due to how marginal these values are, and because it isn't
// worth the complexity to implement differentation
pub const DUST: u64 = 546;

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum TransactionError {
  #[error("no inputs were specified")]
  NoInputs,
  #[error("no outputs were created")]
  NoOutputs,
  #[error("a specified payment's amount was less than bitcoin's required minimum")]
  DustPayment,
  #[error("too much data was specified")]
  TooMuchData,
  #[error("an overflow occurred when evaluating this transaction")]
  Overflow,
  #[error("fee was too low to pass the default minimum fee rate")]
  TooLowFee,
  #[error("not enough funds for these payments")]
  NotEnoughFunds { inputs: u64, payments: u64, fee: u64 },
  #[error("transaction was too large")]
  TooLargeTransaction,
}

/// A signable transaction, clone-able across attempts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignableTransaction {
  tx: Transaction,
  offsets: Vec<Scalar>,
  prevouts: Vec<TxOut>,
  needed_fee: u64,
}

impl SignableTransaction {
  fn calculate_weight_vbytes(inputs: usize, tx_outs: Vec<TxOut>) -> (u64, u64) {
    // Expand this a full transaction in order to use the `bitcoin` library's `weight` function
    let weight = (Transaction {
      version: Version(2),
      lock_time: LockTime::ZERO,
      input: vec![
        TxIn {
          // This is a fixed size
          // See https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
          previous_output: OutPoint::default(),
          // This is empty for a Taproot spend
          script_sig: ScriptBuf::new(),
          // This is fixed size, yet we do use Sequence::MAX
          sequence: Sequence::MAX,
          // Our witnesses contains a single 64-byte signature
          witness: Witness::from_slice(&[vec![0; 64]])
        };
        inputs
      ],
      output: tx_outs,
    })
    .weight();

    // Now calculate the size in vbytes

    /*
      "Virtual transaction size" is weight ceildiv 4 per
      https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki

      https://github.com/bitcoin/bitcoin/blob/306ccd4927a2efe325c8d84be1bdb79edeb29b04
        /src/policy/policy.cpp#L295-L298
      implements this almost as expected, with an additional consideration to signature operations

      Signature operations (the second argument of the following call) do not count Taproot
      signatures per https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#cite_ref-11-0

      We don't risk running afoul of the Taproot signature limit as it allows at least one per
      input, which is all we use
    */
    (
      weight.to_wu(),
      u64::try_from(bitcoin::policy::get_virtual_tx_size(
        i64::try_from(weight.to_wu()).unwrap(),
        0i64,
      ))
      .unwrap(),
    )
  }

  /// Returns the fee necessary for this transaction to achieve the fee rate specified at
  /// construction.
  ///
  /// The actual fee this transaction will use is `sum(inputs) - sum(outputs)`.
  pub fn needed_fee(&self) -> u64 {
    self.needed_fee
  }

  /// Returns the fee this transaction will use.
  pub fn fee(&self) -> u64 {
    self.prevouts.iter().map(|prevout| prevout.value.to_sat()).sum::<u64>() -
      self.tx.output.iter().map(|prevout| prevout.value.to_sat()).sum::<u64>()
  }

  /// Create a new [`SignableTransaction`].
  ///
  /// If a change address is specified, any leftover funds will be sent to it if the leftover funds
  /// exceed the minimum output amount ([`DUST`]). If a change address isn't specified, all
  /// leftover funds will become part of the paid fee.
  ///
  /// If data is specified, an `OP_RETURN` output will be added with it.
  pub fn new(
    inputs: &[ReceivedOutput],
    payments: &[(ScriptBuf, u64)],
    change: Option<ScriptBuf>,
    data: Option<Vec<u8>>,
    fee_per_vbyte: u64,
  ) -> Result<SignableTransaction, TransactionError> {
    if inputs.is_empty() {
      Err(TransactionError::NoInputs)?;
    }

    for (_, amount) in payments {
      if *amount < DUST {
        Err(TransactionError::DustPayment)?;
      }
    }

    if data.as_ref().map(Vec::len).unwrap_or(0) > 80 {
      Err(TransactionError::TooMuchData)?;
    }

    let Some(input_sat) =
      inputs.iter().map(|input| input.output.value.to_sat()).try_fold(0u64, u64::checked_add)
    else {
      Err(TransactionError::Overflow)?
    };

    let Some(payment_sat) =
      payments.iter().map(|payment| payment.1).try_fold(0u64, u64::checked_add)
    else {
      Err(TransactionError::Overflow)?
    };
    let mut tx_outs = payments
      .iter()
      .map(|payment| TxOut { value: Amount::from_sat(payment.1), script_pubkey: payment.0.clone() })
      .collect::<Vec<_>>();

    // Add the `OP_RETURN` output, if specified
    if let Some(data) = data {
      tx_outs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(
          PushBytesBuf::try_from(data)
            .expect("data didn't fit into PushBytes depsite being checked"),
        ),
      });
    }

    /*
      We first check the length of inputs, outputs isn't absurd to ensure we can represent the
      weight. This works so long as the size per input/output structuring is less than
      `usize::MAX / MAX_STANDARD_TX_WEIGHT`, which is reasonably true.
    */
    #[expect(clippy::as_conversions)]
    const {
      let max_weight: u32 = bitcoin::policy::MAX_STANDARD_TX_WEIGHT;
      assert!(usize::BITS >= u32::BITS);
      // `1024` is assumed to be greater than the size of a Taproot input and an output's structure
      assert!((usize::MAX / (max_weight as usize)) > 1024);
    }
    if inputs.len().saturating_add(
      payments
        .iter()
        .map(|payment| &payment.0)
        .chain(change.as_ref())
        .fold(0usize, |accum, script| accum.saturating_add(script.as_bytes().len())),
    ) >= usize::try_from(bitcoin::policy::MAX_STANDARD_TX_WEIGHT).unwrap()
    {
      // This may be slightly overzealous if a change output which would be unused causes us to
      // pass the limit, but always erroring on a change output which would always error is fine
      Err(TransactionError::TooLargeTransaction)?;
    }

    // If there's a change address, check if there's change to give it
    if let Some(change) = change {
      let (_, vbytes_with_change) = Self::calculate_weight_vbytes(inputs.len(), {
        let mut tx_outs = tx_outs.clone();
        // Use a 0 value since we're currently unsure what the change amount will be, and since
        // the value is fixed size (so any value could be used here)
        tx_outs.push(TxOut { value: Amount::ZERO, script_pubkey: change.clone() });
        tx_outs
      });

      // Update the fee
      let fee_with_change =
        fee_per_vbyte.checked_mul(vbytes_with_change).ok_or(TransactionError::Overflow)?;
      if let Some(value) = input_sat
        .checked_sub(payment_sat)
        .and_then(|remaining| remaining.checked_sub(fee_with_change))
        .filter(|value| *value >= DUST)
      {
        tx_outs.push(TxOut { value: Amount::from_sat(value), script_pubkey: change });
      }
    }

    if tx_outs.is_empty() {
      Err(TransactionError::NoOutputs)?;
    }

    let vbytes = {
      let (weight, vbytes) = Self::calculate_weight_vbytes(inputs.len(), tx_outs.clone());
      if weight > u64::from(bitcoin::policy::MAX_STANDARD_TX_WEIGHT) {
        Err(TransactionError::TooLargeTransaction)?;
      }
      vbytes
    };

    let needed_fee = fee_per_vbyte.checked_mul(vbytes).ok_or(TransactionError::Overflow)?;

    if input_sat
      .checked_sub(payment_sat)
      .and_then(|remaining| remaining.checked_sub(needed_fee))
      .is_none()
    {
      Err(TransactionError::NotEnoughFunds {
        inputs: input_sat,
        payments: payment_sat,
        fee: needed_fee,
      })?;
    }

    /*
      If this transaction is too large to effect a sufficient fee rate, and we added a change
      output, it may be possible to achieve the necessary fee rate by dropping the change output.
      We don't include support for such an edge case as it goes against the caller's intent by
      dropping the specified change output to force a too-low specified fee to be usable.
    */
    // `bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE` is in sats/kilo-vbyte
    if needed_fee <
      ((u64::from(bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE)
        .checked_mul(vbytes)
        .ok_or(TransactionError::Overflow))? /
        1000)
    {
      Err(TransactionError::TooLowFee)?;
    }

    Ok(SignableTransaction {
      tx: Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: inputs
          .iter()
          .map(|input| TxIn {
            previous_output: input.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
          })
          .collect(),
        output: tx_outs,
      },
      offsets: inputs.iter().map(|input| input.offset).collect(),
      prevouts: inputs.iter().map(|input| input.output.clone()).collect(),
      needed_fee,
    })
  }

  /// Returns the TX ID of the transaction this will create.
  pub fn txid(&self) -> [u8; 32] {
    let mut res = self.tx.compute_txid().to_byte_array();
    res.reverse();
    res
  }

  /// Returns the transaction, sans witness, this will create if signed.
  pub fn transaction(&self) -> &Transaction {
    &self.tx
  }

  /// Create a multisig machine for this transaction.
  ///
  /// This will return [`None`] if the wrong keys are used.
  pub fn multisig(self, keys: &ThresholdKeys<Secp256k1>) -> Option<TransactionMachine> {
    let mut sigs = vec![];
    for i in 0 .. self.tx.input.len() {
      // TODO: `ThresholdKeys` -> `struct WithUnspendableScriptPath(ThresholdKeys)`
      //   -> `WithUnspendableScriptPath::address(&self)` to ensure the following never deviates
      let offset = keys.clone().offset(self.offsets[i]);
      if super::address(offset.group_key())? != self.prevouts[i].script_pubkey {
        None?;
      }
      sigs.push(AlgorithmMachine::new(
        Schnorr::new(),
        super::tweak_with_unspendable_script_path(offset),
      ));
    }

    Some(TransactionMachine { tx: self, sigs })
  }
}

/// A FROST signing machine to produce a Bitcoin transaction.
///
/// This does not support caching its preprocess. When `sign` is called, `message` must be empty.
/// This will panic if either `cache`, `from_cache` is called or `message` isn't empty.
pub struct TransactionMachine {
  tx: SignableTransaction,
  sigs: Vec<AlgorithmMachine<Secp256k1, Schnorr>>,
}

impl PreprocessMachine for TransactionMachine {
  type Preprocess = Vec<Preprocess<Secp256k1, ()>>;
  type Signature = Transaction;
  type SignMachine = TransactionSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    let mut preprocesses = Vec::with_capacity(self.sigs.len());
    let sigs = self
      .sigs
      .drain(..)
      .map(|sig| {
        let (sig, preprocess) = sig.preprocess(rng);
        preprocesses.push(preprocess);
        sig
      })
      .collect();

    (TransactionSignMachine { tx: self.tx, sigs }, preprocesses)
  }
}

pub struct TransactionSignMachine {
  tx: SignableTransaction,
  sigs: Vec<AlgorithmSignMachine<Secp256k1, Schnorr>>,
}

impl SignMachine<Transaction> for TransactionSignMachine {
  type Params = ();
  type Keys = ThresholdKeys<Secp256k1>;
  type Preprocess = Vec<Preprocess<Secp256k1, ()>>;
  type SignatureShare = Vec<SignatureShare<Secp256k1>>;
  type SignatureMachine = TransactionSignatureMachine;

  fn cache(self) -> CachedPreprocess {
    unimplemented!(
      "Bitcoin transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn from_cache(
    (): (),
    _: ThresholdKeys<Secp256k1>,
    _: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    unimplemented!(
      "Bitcoin transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    self.sigs.iter().map(|sig| sig.read_preprocess(reader)).collect()
  }

  fn sign(
    mut self,
    commitments: HashMap<Participant, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(TransactionSignatureMachine, Self::SignatureShare), FrostError> {
    assert!(
      msg.is_empty(),
      "message was passed to the TransactionSignMachine when it generates its own"
    );

    let commitments = (0 .. self.sigs.len())
      .map(|c| {
        commitments
          .iter()
          .map(|(l, commitments)| (*l, commitments[c].clone()))
          .collect::<HashMap<_, _>>()
      })
      .collect::<Vec<_>>();

    let mut cache = SighashCache::new(&self.tx.tx);
    // Sign committing to all inputs
    let prevouts = Prevouts::All(&self.tx.prevouts);

    let mut shares = Vec::with_capacity(self.sigs.len());
    let sigs = self
      .sigs
      .drain(..)
      .enumerate()
      .map(|(i, sig)| {
        let (sig, share) = sig.sign(
          commitments[i].clone(),
          cache
            .taproot_key_spend_signature_hash(i, &prevouts, TapSighashType::Default)
            // This should never happen since the inputs align with the TX the cache was
            // constructed with, and because i is always < prevouts.len()
            .expect("taproot_key_spend_signature_hash failed to return a hash")
            .as_ref(),
        )?;
        shares.push(share);
        Ok(sig)
      })
      .collect::<Result<_, _>>()?;

    Ok((TransactionSignatureMachine { tx: self.tx.tx, sigs }, shares))
  }
}

pub struct TransactionSignatureMachine {
  tx: Transaction,
  sigs: Vec<AlgorithmSignatureMachine<Secp256k1, Schnorr>>,
}

impl SignatureMachine<Transaction> for TransactionSignatureMachine {
  type SignatureShare = Vec<SignatureShare<Secp256k1>>;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    self.sigs.iter().map(|sig| sig.read_share(reader)).collect()
  }

  fn complete(
    mut self,
    mut shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    for (input, schnorr) in self.tx.input.iter_mut().zip(self.sigs.drain(..)) {
      let sig = schnorr.complete(
        shares.iter_mut().map(|(l, shares)| (*l, shares.remove(0))).collect::<HashMap<_, _>>(),
      )?;

      let mut witness = Witness::new();
      witness.push(sig);
      input.witness = witness;
    }

    Ok(self.tx)
  }
}

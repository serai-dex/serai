use std::{
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::RngCore;

use transcript::{Transcript, RecommendedTranscript};

use k256::{elliptic_curve::sec1::ToEncodedPoint, Scalar};
use frost::{
  curve::{Ciphersuite, Secp256k1},
  ThresholdKeys, FrostError,
  algorithm::Schnorr,
  sign::*,
};

use bitcoin::{
  hashes::Hash,
  consensus::encode::{Decodable, serialize},
  util::sighash::{SchnorrSighashType, SighashCache, Prevouts},
  OutPoint, Script, Sequence, Witness, TxIn, TxOut, PackedLockTime, Transaction, Address,
};

use crate::crypto::{BitcoinHram, make_even};

/// A spendable output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpendableOutput {
  /// The scalar offset to obtain the key usable to spend this output.
  /// Enables HDKD systems.
  pub offset: Scalar,
  /// The output to spend.
  pub output: TxOut,
  /// The TX ID and vout of the output to spend.
  pub outpoint: OutPoint,
}

impl SpendableOutput {
  /// Obtain a unique ID for this output.
  pub fn id(&self) -> [u8; 36] {
    serialize(&self.outpoint).try_into().unwrap()
  }

  /// Read a SpendableOutput from a generic satisfying Read.
  pub fn read<R: Read>(r: &mut R) -> io::Result<SpendableOutput> {
    Ok(SpendableOutput {
      offset: Secp256k1::read_F(r)?,
      output: TxOut::consensus_decode(r)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid TxOut"))?,
      outpoint: OutPoint::consensus_decode(r)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid OutPoint"))?,
    })
  }

  /// Write a SpendableOutput to a generic satisfying Write.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.offset.to_bytes())?;
    w.write_all(&serialize(&self.output))?;
    w.write_all(&serialize(&self.outpoint))
  }

  /// Serialize a SpendableOutput to a Vec<u8>.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).unwrap();
    res
  }
}

/// A signable transaction, clone-able across attempts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignableTransaction(Transaction, Vec<Scalar>, Vec<TxOut>);

impl SignableTransaction {
  fn calculate_weight(inputs: usize, payments: &[(Address, u64)], change: Option<&Address>) -> u64 {
    let mut tx = Transaction {
      version: 2,
      lock_time: PackedLockTime::ZERO,
      input: vec![
        TxIn {
          previous_output: OutPoint::default(),
          script_sig: Script::new(),
          sequence: Sequence::MAX,
          witness: Witness::from_vec(vec![vec![0; 64]])
        };
        inputs
      ],
      output: payments
        .iter()
        .map(|payment| TxOut { value: payment.1, script_pubkey: payment.0.script_pubkey() })
        .collect(),
    };
    if let Some(change) = change {
      tx.output.push(TxOut { value: 0, script_pubkey: change.script_pubkey() });
    }
    u64::try_from(tx.weight()).unwrap()
  }

  /// Create a new signable-transaction.
  pub fn new(
    mut inputs: Vec<SpendableOutput>,
    payments: &[(Address, u64)],
    change: Option<Address>,
    fee: u64,
  ) -> Option<SignableTransaction> {
    if inputs.is_empty() || (payments.is_empty() && change.is_none()) {
      return None;
    }

    let input_sat = inputs.iter().map(|input| input.output.value).sum::<u64>();
    let offsets = inputs.iter().map(|input| input.offset).collect();
    let tx_ins = inputs
      .iter()
      .map(|input| TxIn {
        previous_output: input.outpoint,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
      })
      .collect::<Vec<_>>();

    let payment_sat = payments.iter().map(|payment| payment.1).sum::<u64>();
    let mut tx_outs = payments
      .iter()
      .map(|payment| TxOut { value: payment.1, script_pubkey: payment.0.script_pubkey() })
      .collect::<Vec<_>>();

    let actual_fee = fee * Self::calculate_weight(tx_ins.len(), payments, None);
    if input_sat < (payment_sat + actual_fee) {
      return None;
    }

    // If there's a change address, check if there's a meaningful change
    if let Some(change) = change.as_ref() {
      let fee_with_change = fee * Self::calculate_weight(tx_ins.len(), payments, Some(change));
      // If there's a non-zero change, add it
      if let Some(value) = input_sat.checked_sub(payment_sat + fee_with_change) {
        tx_outs.push(TxOut { value, script_pubkey: change.script_pubkey() });
      }
    }

    // TODO: Drop outputs which BTC will consider spam (outputs worth less than the cost to spend
    // them)

    Some(SignableTransaction(
      Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: tx_ins, output: tx_outs },
      offsets,
      inputs.drain(..).map(|input| input.output).collect(),
    ))
  }

  /// Create a multisig machine for this transaction.
  pub async fn multisig(
    self,
    keys: ThresholdKeys<Secp256k1>,
    mut transcript: RecommendedTranscript,
  ) -> Result<TransactionMachine, FrostError> {
    transcript.domain_separate(b"bitcoin_transaction");
    transcript.append_message(b"root_key", keys.group_key().to_encoded_point(true).as_bytes());

    // Transcript the inputs and outputs
    let tx = &self.0;
    for input in &tx.input {
      transcript.append_message(b"input_hash", input.previous_output.txid.as_hash().into_inner());
      transcript.append_message(b"input_output_index", input.previous_output.vout.to_le_bytes());
    }
    for payment in &tx.output {
      transcript.append_message(b"output_script", payment.script_pubkey.as_bytes());
      transcript.append_message(b"output_amount", payment.value.to_le_bytes());
    }

    let mut sigs = vec![];
    for i in 0 .. tx.input.len() {
      // TODO: Use the above transcript here
      sigs.push(
        AlgorithmMachine::new(
          Schnorr::<Secp256k1, BitcoinHram>::new(),
          keys.clone().offset(self.1[i]),
        )
        .unwrap(),
      );
    }

    Ok(TransactionMachine { tx: self, transcript, sigs })
  }
}

/// A FROST signing machine to produce a Bitcoin transaction.
pub struct TransactionMachine {
  tx: SignableTransaction,
  transcript: RecommendedTranscript,
  sigs: Vec<AlgorithmMachine<Secp256k1, Schnorr<Secp256k1, BitcoinHram>>>,
}

impl PreprocessMachine for TransactionMachine {
  type Preprocess = Vec<Preprocess<Secp256k1, ()>>;
  type Signature = Transaction;
  type SignMachine = TransactionSignMachine;

  fn preprocess<R: RngCore + rand_core::CryptoRng>(
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

    (TransactionSignMachine { tx: self.tx, transcript: self.transcript, sigs }, preprocesses)
  }
}

pub struct TransactionSignMachine {
  tx: SignableTransaction,
  transcript: RecommendedTranscript,
  sigs: Vec<AlgorithmSignMachine<Secp256k1, Schnorr<Secp256k1, BitcoinHram>>>,
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
    _: (),
    _: ThresholdKeys<Secp256k1>,
    _: CachedPreprocess,
  ) -> Result<Self, FrostError> {
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
    commitments: HashMap<u16, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(TransactionSignatureMachine, Self::SignatureShare), FrostError> {
    if !msg.is_empty() {
      Err(FrostError::InternalError(
        "message was passed to the TransactionMachine when it generates its own",
      ))?;
    }

    let commitments = (0 .. self.sigs.len())
      .map(|c| {
        commitments
          .iter()
          .map(|(l, commitments)| (*l, commitments[c].clone()))
          .collect::<HashMap<_, _>>()
      })
      .collect::<Vec<_>>();

    let mut cache = SighashCache::new(&self.tx.0);
    let prevouts = Prevouts::All(&self.tx.2);

    let mut shares = Vec::with_capacity(self.sigs.len());
    let sigs = self
      .sigs
      .drain(..)
      .enumerate()
      .map(|(i, sig)| {
        let tx_sighash = cache
          .taproot_key_spend_signature_hash(i, &prevouts, SchnorrSighashType::Default)
          .unwrap();

        let (sig, share) = sig.sign(commitments[i].clone(), &tx_sighash)?;
        shares.push(share);
        Ok(sig)
      })
      .collect::<Result<_, _>>()?;

    Ok((TransactionSignatureMachine { tx: self.tx.0, sigs }, shares))
  }
}

pub struct TransactionSignatureMachine {
  tx: Transaction,
  sigs: Vec<AlgorithmSignatureMachine<Secp256k1, Schnorr<Secp256k1, BitcoinHram>>>,
}

impl SignatureMachine<Transaction> for TransactionSignatureMachine {
  type SignatureShare = Vec<SignatureShare<Secp256k1>>;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    self.sigs.iter().map(|sig| sig.read_share(reader)).collect()
  }

  fn complete(
    mut self,
    mut shares: HashMap<u16, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    for (input, schnorr) in self.tx.input.iter_mut().zip(self.sigs.drain(..)) {
      let mut sig = schnorr.complete(
        shares.iter_mut().map(|(l, shares)| (*l, shares.remove(0))).collect::<HashMap<_, _>>(),
      )?;

      // TODO: Implement BitcoinSchnorr Algorithm to handle this
      let offset;
      (sig.R, offset) = make_even(sig.R);
      sig.s += Scalar::from(offset);

      let mut witness: Witness = Witness::new();
      witness.push(&sig.serialize()[1 .. 65]);
      input.witness = witness;
    }

    Ok(self.tx)
  }
}

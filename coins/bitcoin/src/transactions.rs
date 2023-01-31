use std::{
  io::{self, Read},
  collections::HashMap,
};

use rand_core::RngCore;

use transcript::{Transcript, RecommendedTranscript};

use k256::{elliptic_curve::sec1::ToEncodedPoint, Scalar};
use frost::{curve::Secp256k1, ThresholdKeys, FrostError, algorithm::Schnorr, sign::*};

use bitcoin::{
  secp256k1::schnorr::Signature,
  hashes::Hash,
  util::{
    schnorr::SchnorrSig,
    sighash::{SchnorrSighashType, SighashCache, Prevouts},
  },
  psbt::{serialize::Serialize, PartiallySignedTransaction},
  OutPoint, Script, Sequence, Witness, TxIn, TxOut, PackedLockTime, Transaction, Address,
};

use crate::crypto::{BitcoinHram, make_even};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignableTransaction {
  pub tx: PartiallySignedTransaction,
}

impl SignableTransaction {
  pub async fn multisig(
    self,
    keys: ThresholdKeys<Secp256k1>,
    mut transcript: RecommendedTranscript,
  ) -> Result<TransactionMachine, FrostError> {
    transcript.domain_separate(b"bitcoin_transaction");
    transcript.append_message(b"root_key", keys.group_key().to_encoded_point(true).as_bytes());

    // Transcript the inputs and outputs
    let tx = &self.tx.unsigned_tx;
    for input in &tx.input {
      transcript.append_message(b"input_hash", input.previous_output.txid.as_hash().into_inner());
      transcript.append_message(b"input_output_index", input.previous_output.vout.to_le_bytes());
    }
    for payment in &tx.output {
      transcript.append_message(b"output_script", payment.script_pubkey.as_bytes());
      transcript.append_message(b"output_amount", payment.value.to_le_bytes());
    }

    let mut sigs = vec![];
    for _ in 0 .. tx.input.len() {
      // TODO: Use the above transcript here
      sigs.push(
        AlgorithmMachine::new(Schnorr::<Secp256k1, BitcoinHram>::new(), keys.clone()).unwrap(),
      );
    }

    Ok(TransactionMachine { signable: self, transcript, sigs })
  }

  pub fn calculate_weight(
    inputs: usize,
    payments: &[(Address, u64)],
    change: Option<&Address>,
  ) -> usize {
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
    tx.weight()
  }
}

pub struct TransactionMachine {
  signable: SignableTransaction,
  transcript: RecommendedTranscript,
  sigs: Vec<AlgorithmMachine<Secp256k1, Schnorr<Secp256k1, BitcoinHram>>>,
}

pub struct TransactionSignMachine {
  signable: SignableTransaction,
  transcript: RecommendedTranscript,
  sigs: Vec<AlgorithmSignMachine<Secp256k1, Schnorr<Secp256k1, BitcoinHram>>>,
}

pub struct TransactionSignatureMachine {
  tx: PartiallySignedTransaction,
  sigs: Vec<AlgorithmSignatureMachine<Secp256k1, Schnorr<Secp256k1, BitcoinHram>>>,
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

    (
      TransactionSignMachine { signable: self.signable, transcript: self.transcript, sigs },
      preprocesses,
    )
  }
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

    let mut cache = SighashCache::new(&self.signable.tx.unsigned_tx);
    let witness = self
      .signable
      .tx
      .inputs
      .iter()
      .map(|input| input.witness_utxo.clone().expect("no witness"))
      .collect::<Vec<_>>();
    let prevouts = Prevouts::All(&witness);

    let mut shares = Vec::with_capacity(self.sigs.len());
    let sigs = self
      .sigs
      .drain(..)
      .enumerate()
      .map(|(index, sig)| {
        let tx_sighash = cache
          .taproot_key_spend_signature_hash(index, &prevouts, SchnorrSighashType::Default)
          .unwrap();

        let (sig, share) = sig.sign(commitments[index].clone(), &tx_sighash)?;
        shares.push(share);
        Ok(sig)
      })
      .collect::<Result<_, _>>()?;
    Ok((TransactionSignatureMachine { tx: self.signable.tx, sigs }, shares))
  }
}

impl SignatureMachine<Transaction> for TransactionSignatureMachine {
  type SignatureShare = Vec<SignatureShare<Secp256k1>>;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    self.sigs.iter().map(|sig| sig.read_share(reader)).collect()
  }

  fn complete(
    mut self,
    shares: HashMap<u16, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    for (i, schnorr) in self.sigs.drain(..).enumerate() {
      let mut sig = schnorr.complete(
        shares.iter().map(|(l, shares)| (*l, shares[i].clone())).collect::<HashMap<_, _>>(),
      )?;

      // TODO: Implement BitcoinSchnorr Algorithm to handle this
      let offset;
      (sig.R, offset) = make_even(sig.R);
      sig.s += Scalar::from(offset);

      let mut script_witness: Witness = Witness::new();
      script_witness.push(
        SchnorrSig {
          sig: Signature::from_slice(&sig.serialize()[1 .. 65]).unwrap(),
          hash_ty: SchnorrSighashType::Default,
        }
        .serialize(),
      );
      self.tx.inputs[i].final_script_witness = Some(script_witness);
    }

    Ok(self.tx.extract_tx())
  }
}

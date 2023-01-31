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
  consensus::encode::{Encodable, Decodable, serialize},
  util::{
    schnorr::SchnorrSig,
    sighash::{SchnorrSighashType, SighashCache, Prevouts},
  },
  psbt::{serialize::Serialize, PartiallySignedTransaction},
  OutPoint, Script, Sequence, Witness, TxIn, TxOut, PackedLockTime, Transaction, Address,
};

use crate::crypto::{BitcoinHram, make_even};

#[derive(Clone, Debug)]
pub struct SpendableOutput {
  pub output: TxOut,
  pub outpoint: OutPoint,
}

impl SpendableOutput {
  pub fn id(&self) -> [u8; 36] {
    serialize(&self.outpoint).try_into().unwrap()
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<SpendableOutput> {
    Ok(SpendableOutput {
      output: TxOut::consensus_decode(r)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid TxOut"))?,
      outpoint: OutPoint::consensus_decode(r)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid OutPoint"))?,
    })
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = serialize(&self.output);
    self.outpoint.consensus_encode(&mut res).unwrap();
    res
  }
}

#[derive(Clone, Debug)]
pub struct SignableTransaction(PartiallySignedTransaction);

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

  pub fn new(
    inputs: Vec<SpendableOutput>,
    payments: &[(Address, u64)],
    change: Option<Address>,
    fee: u64,
  ) -> Option<SignableTransaction> {
    let input_sat = inputs.iter().map(|input| input.output.value).sum::<u64>();
    let txins = inputs
      .iter()
      .map(|input| TxIn {
        previous_output: input.outpoint,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
      })
      .collect::<Vec<_>>();

    let payment_sat = payments.iter().map(|payment| payment.1).sum::<u64>();
    let mut txouts = payments
      .iter()
      .map(|payment| TxOut { value: payment.1, script_pubkey: payment.0.script_pubkey() })
      .collect::<Vec<_>>();

    let actual_fee = fee * Self::calculate_weight(txins.len(), payments, None);

    if payment_sat > (input_sat - actual_fee) {
      return None;
    }

    // If there's a change address, check if there's a meaningful change
    if let Some(change) = change.as_ref() {
      let fee_with_change = fee * Self::calculate_weight(txins.len(), payments, Some(change));
      // If there's a non-zero change, add it
      if let Some(value) = input_sat.checked_sub(payment_sat + fee_with_change) {
        txouts.push(TxOut { value, script_pubkey: change.script_pubkey() });
      }
    }

    // TODO: Drop outputs which BTC will consider spam (outputs worth less than the cost to spend
    // them)

    let new_transaction =
      Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: txins, output: txouts };

    let mut pst = PartiallySignedTransaction::from_unsigned_tx(new_transaction).unwrap();
    debug_assert_eq!(pst.inputs.len(), inputs.len());
    for (pst, input) in pst.inputs.iter_mut().zip(inputs.iter()) {
      pst.witness_utxo = Some(input.output.clone());
    }

    Some(SignableTransaction(pst))
  }

  pub async fn multisig(
    self,
    keys: ThresholdKeys<Secp256k1>,
    mut transcript: RecommendedTranscript,
  ) -> Result<TransactionMachine, FrostError> {
    transcript.domain_separate(b"bitcoin_transaction");
    transcript.append_message(b"root_key", keys.group_key().to_encoded_point(true).as_bytes());

    // Transcript the inputs and outputs
    let tx = &self.0.unsigned_tx;
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

    Ok(TransactionMachine { pst: self.0, transcript, sigs })
  }
}

pub struct TransactionMachine {
  pst: PartiallySignedTransaction,
  transcript: RecommendedTranscript,
  sigs: Vec<AlgorithmMachine<Secp256k1, Schnorr<Secp256k1, BitcoinHram>>>,
}

pub struct TransactionSignMachine {
  pst: PartiallySignedTransaction,
  transcript: RecommendedTranscript,
  sigs: Vec<AlgorithmSignMachine<Secp256k1, Schnorr<Secp256k1, BitcoinHram>>>,
}

pub struct TransactionSignatureMachine {
  pst: PartiallySignedTransaction,
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

    (TransactionSignMachine { pst: self.pst, transcript: self.transcript, sigs }, preprocesses)
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

    let mut cache = SighashCache::new(&self.pst.unsigned_tx);
    let witness = self
      .pst
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
    Ok((TransactionSignatureMachine { pst: self.pst, sigs }, shares))
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
      self.pst.inputs[i].final_script_witness = Some(script_witness);
    }

    Ok(self.pst.extract_tx())
  }
}

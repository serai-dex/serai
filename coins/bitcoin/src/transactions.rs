use bitcoin::{
  util::{
    schnorr::{SchnorrSig},
    sighash::{SchnorrSighashType},
  },
  psbt::{serialize::Serialize, PartiallySignedTransaction},
  Witness,
};
use frost::{
  algorithm::Schnorr,
  curve::{Secp256k1},
  FrostError, ThresholdKeys,
  sign::{
    Preprocess, CachedPreprocess, SignatureShare, PreprocessMachine, SignMachine, SignatureMachine,
    AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
};
use crate::crypto::{BitcoinHram, make_even, taproot_key_spend_signature_hash};
use rand_core::{RngCore};

use core::{fmt::Debug};
use std::{
  io::{self, Read},
  collections::{HashMap, BTreeMap},
};

use k256::{elliptic_curve::sec1::ToEncodedPoint, Scalar};
use transcript::{Transcript, RecommendedTranscript};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignableTransaction {
  pub tx: PartiallySignedTransaction,
}

impl SignableTransaction {
  /// Create a FROST signing machine out of this signable transaction.
  /// The height is the Bitcoin blockchain height to synchronize around.
  pub async fn multisig(
    self,
    keys: ThresholdKeys<Secp256k1>,
    mut transcript: RecommendedTranscript,
    height: usize,
  ) -> Result<TransactionMachine, FrostError> {
    transcript.domain_separate(b"bitcoin_transaction");
    transcript.append_message(b"height", u64::try_from(height).unwrap().to_le_bytes());
    transcript.append_message(b"spend_key", keys.group_key().to_encoded_point(true).as_bytes());

    let raw_tx = self.tx.clone().extract_tx();
    let mut sigs = vec![];
    let algorithm = Schnorr::<Secp256k1, BitcoinHram>::new();
    for (i, input) in raw_tx.input.iter().enumerate() {
      let txid: [u8; 32] = input.previous_output.txid.to_vec()[0..32].try_into().unwrap();
      transcript.append_message(b"input_hash", txid);
      transcript.append_message(b"input_output_index", input.previous_output.vout.to_le_bytes());
      transcript.append_message(
        b"input_shared_key",
        self.tx.inputs[i].tap_internal_key.unwrap().serialize(),
      );

      sigs.push(AlgorithmMachine::new(algorithm.clone(), keys.clone()).unwrap());
    }

    for payment in raw_tx.output {
      //TODO: need address generator function to generate address from script_pubkey
      transcript.append_message(b"payment_address", payment.script_pubkey.as_bytes());
      transcript.append_message(b"payment_amount", payment.value.to_le_bytes());
    }

    for _ in self.tx.inputs.iter() {
      sigs.push(AlgorithmMachine::new(algorithm.clone(), keys.clone()).unwrap());
    }

    return Ok(TransactionMachine { signable: self, transcript, sigs });
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
  type Signature = PartiallySignedTransaction;
  type SignMachine = TransactionSignMachine;

  fn preprocess<R: RngCore + rand_core::CryptoRng>(
    mut self,
    rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    let mut preprocesses = Vec::with_capacity(self.sigs.len());
    let all_sigs = self
      .sigs
      .drain(..)
      .map(|sig| {
        let (sig, preprocess) = sig.preprocess(rng);
        preprocesses.push(preprocess);
        sig
      })
      .collect();
    (
      TransactionSignMachine {
        signable: self.signable,
        transcript: self.transcript,
        sigs: all_sigs,
      },
      preprocesses,
    )
  }
}

impl SignMachine<PartiallySignedTransaction> for TransactionSignMachine {
  type Params = ();
  type Keys = ThresholdKeys<Secp256k1>;
  type Preprocess = Vec<Preprocess<Secp256k1, ()>>;
  type SignatureShare = Vec<SignatureShare<Secp256k1>>;
  type SignatureMachine = TransactionSignatureMachine;

  fn cache(self) -> Zeroizing<CachedPreprocess> {
    unimplemented!(
      "Bitcoin transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn from_cache(
    _: (),
    _: ThresholdKeys<Secp256k1>,
    _: Zeroizing<CachedPreprocess>,
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
    mut commitments: HashMap<u16, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(TransactionSignatureMachine, Self::SignatureShare), FrostError> {
    if !msg.is_empty() {
      Err(FrostError::InternalError(
        "message was passed to the TransactionMachine when it generates its own",
      ))?;
    }
    let mut msg_list = Vec::new();
    for i in 0..self.signable.tx.inputs.len() {
      let (tx_sighash, _) = taproot_key_spend_signature_hash(&self.signable.tx, i).unwrap();
      msg_list.push(tx_sighash);
    }

    let included = commitments.keys().into_iter().cloned().collect::<Vec<_>>();
    let mut commitments = (0..self.sigs.len())
      .map(|c| {
        included
          .iter()
          .map(|l| {
            let preprocess =
              commitments.get_mut(l).ok_or(FrostError::MissingParticipant(*l))?[c].clone();
            Ok((*l, preprocess))
          })
          .collect::<Result<HashMap<_, _>, _>>()
      })
      .collect::<Result<Vec<_>, _>>()?;

    let mut shares = Vec::with_capacity(self.sigs.len());
    let sigs = self
      .sigs
      .drain(..)
      .enumerate()
      .map(|(index, sig)| {
        let (sig, share) = sig.sign(commitments.remove(0), &msg_list.remove(index))?;
        shares.push(share);
        Ok(sig)
      })
      .collect::<Result<_, _>>()?;
    Ok((TransactionSignatureMachine { tx: self.signable.tx, sigs: sigs }, shares))
  }
}

impl SignatureMachine<PartiallySignedTransaction> for TransactionSignatureMachine {
  type SignatureShare = Vec<SignatureShare<Secp256k1>>;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    self.sigs.iter().map(|clsag| clsag.read_share(reader)).collect()
  }

  fn complete(
    mut self,
    shares: HashMap<u16, Self::SignatureShare>,
  ) -> Result<PartiallySignedTransaction, FrostError> {
    for (i, schnorr) in self.sigs.drain(..).enumerate() {
      let mut _sig = schnorr.complete(
        shares.iter().map(|(l, shares)| (*l, shares[i].clone())).collect::<HashMap<_, _>>(),
      )?;
      let mut _offset = 0;
      (_sig.R, _offset) = make_even(_sig.R);
      _sig.s += Scalar::from(_offset);

      let temp_sig = secp256k1::schnorr::Signature::from_slice(&_sig.serialize()[1..65]).unwrap();
      let sig = SchnorrSig { sig: temp_sig, hash_ty: SchnorrSighashType::All };
      self.tx.inputs[i].tap_key_sig = Some(sig);

      let mut script_witness: Witness = Witness::new();
      script_witness.push(self.tx.inputs[i].tap_key_sig.unwrap().serialize());
      self.tx.inputs[i].final_script_witness = Some(script_witness);
      self.tx.inputs[i].partial_sigs = BTreeMap::new();
      self.tx.inputs[i].sighash_type = None;
      self.tx.inputs[i].redeem_script = None;
      self.tx.inputs[i].witness_script = None;
      self.tx.inputs[i].bip32_derivation = BTreeMap::new();
    }
    Ok(self.tx)
  }
}

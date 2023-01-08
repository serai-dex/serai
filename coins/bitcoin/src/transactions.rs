use bitcoin::{
  Txid, util::schnorr::{self,SchnorrSig}, schnorr::TapTweak, util::taproot, util::psbt,
  util::sighash::SchnorrSighashType, psbt::PartiallySignedTransaction, Script,
};
use frost::{
  algorithm::Schnorr,
  curve::{Secp256k1, Ciphersuite},
  FrostError, ThresholdKeys,
  sign::{
    Writable, Preprocess, CachedPreprocess, SignatureShare, PreprocessMachine, SignMachine,
    SignatureMachine, AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
  algorithm::{WriteAddendum, Algorithm},
  tests::{algorithm_machines, key_gen, sign},
};
use crate::crypto::{BitcoinHram, make_even, SignerError, taproot_sighash};
use rand_core::{OsRng, RngCore};

use core::{ops::Deref, fmt::Debug};
use std::{
  io::{self, Read, Write},
  sync::{Arc, RwLock},
  collections::HashMap,
};

use k256::{elliptic_curve::sec1::ToEncodedPoint};
use transcript::{Transcript, RecommendedTranscript};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignableTransaction {
  pub tx : PartiallySignedTransaction
}

impl SignableTransaction {
  /// Create a FROST signing machine out of this signable transaction.
  /// The height is the Monero blockchain height to synchronize around.
  pub async fn multisig(
    self,
    keys: ThresholdKeys<Secp256k1>,
    mut transcript: RecommendedTranscript,
    height: usize,
  ) -> Result<TransactionMachine, FrostError> {
    transcript.domain_separate(b"bitcoin_transaction");
    transcript.append_message(b"height", u64::try_from(height).unwrap().to_le_bytes());
    transcript.append_message(b"spend_key", keys.group_key().to_encoded_point(true).as_bytes());
    for input in &self.tx.inputs {
      //transcript.append_message(b"input_hash", input.output.absolute.tx);
      //transcript.append_message(b"input_output_index", [input.output.absolute.o]);
      //transcript.append_message(b"input_shared_key", input.key_offset().to_bytes());
    }

    for payment in &self.tx.clone().extract_tx().output {
      //transcript.append_message(b"payment_address", payment.0.to_string().as_bytes());
      transcript.append_message(b"payment_amount", payment.value.to_le_bytes());
    }

    let mut sigs = vec![];
    
    for (i, input) in self.tx.inputs.iter().enumerate() {
      let algorithm= Schnorr::<Secp256k1, BitcoinHram>::new();
      sigs.push(AlgorithmMachine::new(algorithm.clone(), keys.clone()).unwrap());
    }


    return Ok(TransactionMachine {
      signable: self,
      transcript,
      sigs,
    });

    //return Err(FrostError::DuplicatedIndex(1));
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

    let mut tx = self.signable.tx;
    /*for (i, one_txinput) in tx.inputs.iter().enumerate() {
      let (tx_sighash ,sighash_type)= taproot_sighash(&tx, i).unwrap();
      tx.inputs[i].tap_key_sig = Some(tx_sighash);
    }*/

    let mut included = commitments.keys().into_iter().cloned().collect::<Vec<_>>();
    let mut commitments = (0 .. self.sigs.len()).map(|c| {
      included
        .iter()
        .map(|l| {
          let preprocess = commitments.get_mut(l).ok_or(FrostError::MissingParticipant(*l))?[c].clone();
          Ok((*l, preprocess))
        })
        .collect::<Result<HashMap<_, _>, _>>()
    })
    .collect::<Result<Vec<_>, _>>()?;

    let mut shares = Vec::with_capacity(self.sigs.len());
    let sigs = self.sigs.drain(..).map(|sig| {
      let (sig, share) = sig.sign(commitments.remove(0), &msg)?;
      shares.push(share);
      Ok(sig)
    })
    .collect::<Result<_, _>>()?;
    Ok((TransactionSignatureMachine { tx, sigs}, shares))
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
      let _sig = schnorr.complete(shares.iter().map(|(l, shares)| (*l, shares[i].clone())).collect::<HashMap<_, _>>())?;
      let temp_sig = secp256k1::schnorr::Signature::from_slice(&_sig.serialize()[1..65]).unwrap();
      let sig = SchnorrSig { sig:temp_sig, hash_ty: SchnorrSighashType::All };
      self.tx.inputs[i].tap_key_sig = Some(sig);
    }
    Ok(self.tx)
  }
}

use bitcoin::{
  util::{
    schnorr::SchnorrSig,
    sighash::{SchnorrSighashType, SighashCache, Prevouts},
  },
  psbt::{serialize::Serialize, PartiallySignedTransaction},
  Witness, VarInt, Address,
};
use frost::{
  algorithm::Schnorr,
  curve::Secp256k1,
  FrostError, ThresholdKeys,
  sign::{
    Preprocess, CachedPreprocess, SignatureShare, PreprocessMachine, SignMachine, SignatureMachine,
    AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
};
use crate::crypto::{BitcoinHram, make_even};
use rand_core::RngCore;

use core::fmt::Debug;
use std::{
  io::{self, Read},
  collections::{HashMap, BTreeMap},
};

use k256::{elliptic_curve::sec1::ToEncodedPoint, Scalar};
use transcript::{Transcript, RecommendedTranscript};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignableTransaction {
  pub tx: PartiallySignedTransaction,
  pub fee: u64,
}

impl SignableTransaction {
  /// Create a FROST signing machine out of this signable transaction.
  /// The height is the Bitcoin blockchain height to synchronize around.
  pub async fn multisig(
    self,
    keys: ThresholdKeys<Secp256k1>,
    mut transcript: RecommendedTranscript,
    number: usize,
  ) -> Result<TransactionMachine, FrostError> {
    transcript.domain_separate(b"bitcoin_transaction");
    transcript.append_message(b"height", u64::try_from(number).unwrap().to_le_bytes());
    transcript.append_message(b"spend_key", keys.group_key().to_encoded_point(true).as_bytes());

    let raw_tx = self.tx.clone().extract_tx();
    let mut sigs = vec![];
    let algorithm = Schnorr::<Secp256k1, BitcoinHram>::new();
    for (i, input) in raw_tx.input.iter().enumerate() {
      let txid: [u8; 32] = input.previous_output.txid.as_ref().try_into().unwrap();
      transcript.append_message(b"input_hash", txid);
      transcript.append_message(b"input_output_index", input.previous_output.vout.to_le_bytes());
      transcript.append_message(
        b"input_internal_key",
        self.tx.inputs[i].tap_internal_key.unwrap().serialize(),
      );

      sigs.push(AlgorithmMachine::new(algorithm.clone(), keys.clone()).unwrap());
    }

    for payment in raw_tx.output {
      //TODO: need address generator function to generate address from script_pubkey
      transcript.append_message(b"output_script", payment.script_pubkey.as_bytes());
      transcript.append_message(b"output_amount", payment.value.to_le_bytes());
    }

    return Ok(TransactionMachine { signable: self, transcript, sigs });
  }

  pub fn calculate_weight(total_inputs: usize, payments: &[(Address, u64)], change: bool) -> usize {
    // version number + segwit marker + segwit flag
    let mut total_weight = 4 * 4;
    total_weight += 1;
    total_weight += 1;
    // number of input
    total_weight += 1 * 4;
    // Previous output hash
    total_weight += total_inputs * 32 * 4;
    // Previous output index
    total_weight += total_inputs * 4 * 4;
    // Script length - Scriptsig is empty
    total_weight += total_inputs * 1 * 4;
    total_weight += total_inputs * 4 * 4;
    // OUTPUTS
    total_weight += 1 * 4;
    // 8 byte value - txout script length - [1-9] byte for script length and script pubkey
    for (address, _) in payments.iter() {
      total_weight += 8 * 4;
      total_weight += VarInt(u64::try_from(address.script_pubkey().len()).unwrap()).len() * 4;
      total_weight += (address.script_pubkey().len()) * 1 * 4;
    }
    if change {
      // Change address script pubkey byte (p2tr)
      total_weight += 8 * 4;
      total_weight += 1 * 4;
      total_weight += 34 * 4;
    }
    // Stack size of p2tr
    total_weight += total_inputs * 1 * 1;
    total_weight += total_inputs * 1 * 1;
    total_weight += total_inputs * 65 * 1;
    // locktime
    total_weight += 4 * 4;

    return total_weight;
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
    mut commitments: HashMap<u16, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(TransactionSignatureMachine, Self::SignatureShare), FrostError> {
    if !msg.is_empty() {
      Err(FrostError::InternalError(
        "message was passed to the TransactionMachine when it generates its own",
      ))?;
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
        let inputs = &self.signable.tx.inputs;
        let all_witness_utxos = (0..inputs.len())
          .map(|i| &inputs[i].witness_utxo)
          .filter_map(|x| x.as_ref())
          .collect::<Vec<_>>();
        let prevouts = Prevouts::All(&all_witness_utxos);

        let tx_sighash = SighashCache::new(&self.signable.tx.unsigned_tx)
          .taproot_key_spend_signature_hash(index, &prevouts, SchnorrSighashType::All)
          .unwrap();

        let (sig, share) = sig.sign(commitments.remove(0), &tx_sighash)?;
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
    self.sigs.iter().map(|sig| sig.read_share(reader)).collect()
  }

  fn complete(
    mut self,
    shares: HashMap<u16, Self::SignatureShare>,
  ) -> Result<PartiallySignedTransaction, FrostError> {
    for (i, schnorr) in self.sigs.drain(..).enumerate() {
      let mut schnorr_signature = schnorr.complete(
        shares.iter().map(|(l, shares)| (*l, shares[i].clone())).collect::<HashMap<_, _>>(),
      )?;
      let mut _offset = 0;
      (schnorr_signature.R, _offset) = make_even(schnorr_signature.R);
      schnorr_signature.s += Scalar::from(_offset);

      let temp_sig =
        secp256k1::schnorr::Signature::from_slice(&schnorr_signature.serialize()[1..65]).unwrap();
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

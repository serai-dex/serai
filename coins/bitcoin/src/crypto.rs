use sha2::{Digest, Sha256};
use frost::{algorithm::Hram, curve::Secp256k1};
use k256::{
  elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, sec1::Tag},
  ProjectivePoint, U256, Scalar,
};
use bitcoin::{
  util::sighash,
  psbt::{self, PartiallySignedTransaction},
  SchnorrSighashType, TxOut,
};

pub fn make_even(mut key: ProjectivePoint) -> (ProjectivePoint, u64) {
  let mut c = 0;
  while key.to_encoded_point(true).tag() == Tag::CompressedOddY {
    key += ProjectivePoint::GENERATOR;
    c += 1;
  }
  (key, c)
}

#[derive(Clone)]
pub struct BitcoinHram {}

impl Hram<Secp256k1> for BitcoinHram {
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    let (R, _) = make_even(*R);

    let r_encoded_point = R.to_encoded_point(true);
    let a_encoded_point = A.to_encoded_point(true);
    const TAG : &[u8; 17] = b"BIP0340/challenge";
    let tag_hash = Sha256::digest(TAG);
    let mut data = Sha256::new();
    data.update(tag_hash);
    data.update(tag_hash);
    data.update(r_encoded_point.x().unwrap());
    data.update(a_encoded_point.x().unwrap());
    data.update(m);

    Scalar::from_uint_reduced(U256::from_be_slice(&data.finalize()))
  }
}

/// Signing error
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignerError {
  /// The private key is missing for the required public key
  MissingKey,
  /// The private key in use has the right fingerprint but derives differently than expected
  InvalidKey,
  /// The user canceled the operation
  UserCanceled,
  /// Input index is out of range
  InputIndexOutOfRange,
  /// The `non_witness_utxo` field of the transaction is required to sign this input
  MissingNonWitnessUtxo,
  /// The `non_witness_utxo` specified is invalid
  InvalidNonWitnessUtxo,
  /// The `witness_utxo` field of the transaction is required to sign this input
  MissingWitnessUtxo,
  /// The `witness_script` field of the transaction is required to sign this input
  MissingWitnessScript,
  /// The fingerprint and derivation path are missing from the psbt input
  MissingHdKeypath,
  /// The psbt contains a non-`SIGHASH_ALL` sighash in one of its input and the user hasn't
  /// explicitly allowed them
  ///
  /// To enable signing transactions with non-standard sighashes set
  /// [`SignOptions::allow_all_sighashes`] to `true`.
  NonStandardSighash,
  /// Invalid SIGHASH for the signing context in use
  InvalidSighash,
  /// Error while computing the hash to sign
  SighashError(sighash::Error),
  /// Error while signing using hardware wallets
  #[cfg(feature = "hardware-signer")]
  HWIError(hwi::error::Error),
}

pub trait PSBTUtils {
  fn get_utxo_for(&self, input_index: usize) -> Option<TxOut>;
}

impl PSBTUtils for PartiallySignedTransaction {
  fn get_utxo_for(&self, input_index: usize) -> Option<TxOut> {
    let tx = &self.unsigned_tx;

    if input_index >= tx.input.len() {
      return None;
    }

    if let Some(input) = self.inputs.get(input_index) {
      if let Some(wit_utxo) = &input.witness_utxo {
        Some(wit_utxo.clone())
      } else if let Some(in_tx) = &input.non_witness_utxo {
        Some(in_tx.output[tx.input[input_index].previous_output.vout as usize].clone())
      } else {
        None
      }
    } else {
      None
    }
  }
}

pub(crate) fn taproot_key_spend_signature_hash(
  psbt: &psbt::PartiallySignedTransaction,
  input_index: usize,
) -> Result<(bitcoin::util::taproot::TapSighashHash, SchnorrSighashType), SignerError> {
  if input_index >= psbt.inputs.len() || input_index >= psbt.unsigned_tx.input.len() {
    return Err(SignerError::InputIndexOutOfRange);
  }

  let sighash_type = SchnorrSighashType::All.into();
  let witness_utxos = (0..psbt.inputs.len()).map(|i| psbt.get_utxo_for(i)).collect::<Vec<_>>();
  let mut all_witness_utxos = vec![];

  let mut cache = sighash::SighashCache::new(&psbt.unsigned_tx);
  let prevouts = if witness_utxos.iter().all(Option::is_some) {
    all_witness_utxos.extend(witness_utxos.iter().filter_map(|x| x.as_ref()));
    sighash::Prevouts::All(&all_witness_utxos)
  } else {
    return Err(SignerError::MissingWitnessUtxo);
  };

  let hash = cache.taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type);

  Ok((hash.unwrap(), sighash_type))
}

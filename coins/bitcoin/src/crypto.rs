use sha2::{Digest, Sha256};
use frost::{algorithm::Hram, curve::Secp256k1};
use k256::{
  elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, sec1::Tag},
  ProjectivePoint, U256, Scalar,sha2::digest::generic_array::GenericArray,
  sha2::digest::generic_array::typenum::U32,
};
use bitcoin::{
  util::sighash,
  psbt::PartiallySignedTransaction,
  SchnorrSighashType,
};
use lazy_static::lazy_static;

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

lazy_static! {
  static ref TAG_HASH : GenericArray<u8, U32> = Sha256::digest(b"BIP0340/challenge");
}

#[allow(clippy::non_snake_case)]
impl Hram<Secp256k1> for BitcoinHram {
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    let (R, _) = make_even(*R);

    let r_encoded_point = R.to_encoded_point(true);
    let a_encoded_point = A.to_encoded_point(true);
    //let tag_hash:GenericArray<u8, U32> = Sha256::digest(b"BIP0340/challenge");
    let mut data = Sha256::new();
    //data.update(TAG_HASH.as_ref());
    data.update(&*TAG_HASH);
    data.update(&*TAG_HASH);
    data.update(r_encoded_point.x().unwrap());
    data.update(a_encoded_point.x().unwrap());
    data.update(m);

    Scalar::from_uint_reduced(U256::from_be_slice(&data.finalize()))
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignerError {
  MissingWitnessUtxo,
  InputIndexOutOfRange,
}

pub(crate) fn taproot_key_spend_signature_hash(
  psbt: &PartiallySignedTransaction,
  input_index: usize,
) -> Result<(bitcoin::util::taproot::TapSighashHash, SchnorrSighashType), SignerError> {
  if input_index >= psbt.inputs.len() || input_index >= psbt.unsigned_tx.input.len() {
    return Err(SignerError::InputIndexOutOfRange);
  }

  let sighash_type = SchnorrSighashType::All.into();
  let witness_utxos = (0..psbt.inputs.len()).map(|i| psbt.inputs[i].witness_utxo.clone()).collect::<Vec<_>>();
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

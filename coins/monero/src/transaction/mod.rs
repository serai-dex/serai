use rand_core::{RngCore, CryptoRng};
use thiserror::Error;

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::EdwardsPoint
};

use monero::{
  cryptonote::hash::{Hashable, Hash8, Hash},
  consensus::encode::{Encodable, VarInt},
  blockdata::transaction::{
    KeyImage,
    TxIn, TxOutTarget, TxOut,
    SubField, ExtraField,
    TransactionPrefix, Transaction
  },
  util::{
    key::PublicKey,
    ringct::{Key, CtKey, EcdhInfo, RctType, RctSigBase, RctSigPrunable, RctSig},
    address::Address
  }
};

use crate::{
  Commitment,
  random_scalar,
  hash, hash_to_scalar,
  key_image, bulletproofs, clsag,
  rpc::{Rpc, RpcError}
};

mod mixins;

#[derive(Error, Debug)]
pub enum TransactionError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("invalid ring member (member {0}, ring size {1})")]
  InvalidRingMember(u8, u8),
  #[error("invalid commitment")]
  InvalidCommitment,
  #[error("no inputs")]
  NoInputs,
  #[error("too many outputs")]
  TooManyOutputs,
  #[error("not enough funds (in {0}, out {1})")]
  NotEnoughFunds(u64, u64),
  #[error("invalid address")]
  InvalidAddress,
  #[error("rpc error ({0})")]
  RpcError(RpcError),
  #[error("invalid transaction ({0})")]
  InvalidTransaction(RpcError)
}

#[derive(Debug)]
pub struct SpendableOutput {
  pub tx: Hash,
  pub o: usize,
  pub key_offset: Scalar,
  pub commitment: Commitment
}

pub fn scan_tx(tx: &Transaction, view: Scalar, spend: EdwardsPoint) -> Vec<SpendableOutput> {
  let mut pubkeys = vec![];
  if tx.tx_pubkey().is_some() {
    pubkeys.push(tx.tx_pubkey().unwrap());
  }
  if tx.tx_additional_pubkeys().is_some() {
    pubkeys.extend(&tx.tx_additional_pubkeys().unwrap());
  }
  let pubkeys: Vec<EdwardsPoint> = pubkeys.iter().map(|key| key.point.decompress()).filter_map(|key| key).collect();

  let rct_sig = tx.rct_signatures.sig.as_ref();
  if rct_sig.is_none() {
    return vec![];
  }
  let rct_sig = rct_sig.unwrap();

  let mut res = vec![];
  for o in 0 .. tx.prefix.outputs.len() {
    let output_key = match tx.prefix.outputs[o].target {
      TxOutTarget::ToScript { .. } => None,
      TxOutTarget::ToScriptHash { .. } => None,
      TxOutTarget::ToKey { key } => key.point.decompress()
    };
    if output_key.is_none() {
      continue;
    }
    let output_key = output_key.unwrap();

    // TODO: This may be replaceable by pubkeys[o]
    for pubkey in &pubkeys {
      // Hs(8Ra || o)
      let key_offset = shared_key(view, pubkey, o);
      let mut commitment = Commitment::zero();

      // P - shared == spend
      if output_key - (&key_offset * &ED25519_BASEPOINT_TABLE) == spend {
        if tx.prefix.outputs[o].amount.0 != 0 {
          commitment.amount = tx.prefix.outputs[o].amount.0;
        } else {
          let amount = match rct_sig.ecdh_info[o] {
            EcdhInfo::Standard { .. } => continue,
            EcdhInfo::Bulletproof { amount } => amount_decryption(amount.0, key_offset)
          };

          // Rebuild the commitment to verify it
          commitment = Commitment::new(commitment_mask(key_offset), amount);
          if commitment.calculate().compress().to_bytes() != rct_sig.out_pk[o].mask.key {
            break;
          }
        }

        res.push(SpendableOutput { tx: tx.hash(), o, key_offset, commitment });
        break;
      }
    }
  }
  res
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignableInput {
  pub(crate) image: EdwardsPoint,
  mixins: Vec<u64>,
  // Ring, the index we're signing for, and the actual commitment behind it
  pub(crate) ring: Vec<[EdwardsPoint; 2]>,
  pub(crate) i: usize,
  pub(crate) commitment: Commitment
}

impl SignableInput {
  pub fn new(
    image: EdwardsPoint,
    mixins: Vec<u64>,
    ring: Vec<[EdwardsPoint; 2]>,
    i: u8,
    commitment: Commitment
  ) -> Result<SignableInput, TransactionError> {
    let n = ring.len();
    if n > u8::MAX.into() {
      Err(TransactionError::InternalError("max ring size in this library is u8 max".to_string()))?;
    }
    if i >= (n as u8) {
      Err(TransactionError::InvalidRingMember(i, n as u8))?;
    }
    let i: usize = i.into();

    // Validate the commitment matches
    if ring[i][1] != commitment.calculate() {
      Err(TransactionError::InvalidCommitment)?;
    }

    Ok(SignableInput { image, mixins, ring, i, commitment })
  }

  #[cfg(feature = "multisig")]
  pub fn context(&self) -> Vec<u8> {
    let mut context = self.image.compress().to_bytes().to_vec();
    for pair in &self.ring {
      // Doesn't include mixins[i] as CLSAG doesn't care and won't be affected by it
      context.extend(&pair[0].compress().to_bytes());
      context.extend(&pair[1].compress().to_bytes());
    }
    context.extend(&u8::try_from(self.i).unwrap().to_le_bytes());
    // Doesn't include commitment as the above ring + index includes the commitment
    context
  }
}

#[allow(non_snake_case)]
fn shared_key(s: Scalar, P: &EdwardsPoint, o: usize) -> Scalar {
  let mut shared = (s * P).mul_by_cofactor().compress().to_bytes().to_vec();
  VarInt(o.try_into().unwrap()).consensus_encode(&mut shared).unwrap();
  hash_to_scalar(&shared)
}

fn commitment_mask(shared_key: Scalar) -> Scalar {
  let mut mask = b"commitment_mask".to_vec();
  mask.extend(shared_key.to_bytes());
  hash_to_scalar(&mask)
}

fn amount_decryption(amount: [u8; 8], key: Scalar) -> u64 {
  let mut amount_mask = b"amount".to_vec();
  amount_mask.extend(key.to_bytes());
  u64::from_le_bytes(amount) ^ u64::from_le_bytes(hash(&amount_mask)[0 .. 8].try_into().unwrap())
}

fn amount_encryption(amount: u64, key: Scalar) -> Hash8 {
  Hash8(amount_decryption(amount.to_le_bytes(), key).to_le_bytes())
}

#[allow(non_snake_case)]
struct Output {
  R: EdwardsPoint,
  dest: EdwardsPoint,
  mask: Scalar,
  amount: Hash8
}

impl Output {
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R, output: (Address, u64), o: usize) -> Result<Output, TransactionError> {
    let r = random_scalar(rng);
    let shared_key = shared_key(
      r,
      &output.0.public_view.point.decompress().ok_or(TransactionError::InvalidAddress)?,
      o
    );
    Ok(
      Output {
        R: &r * &ED25519_BASEPOINT_TABLE,
        dest: (
          (&shared_key * &ED25519_BASEPOINT_TABLE) +
          output.0.public_spend.point.decompress().ok_or(TransactionError::InvalidAddress)?
        ),
        mask: commitment_mask(shared_key),
        amount: amount_encryption(output.1, shared_key)
      }
    )
  }
}

pub async fn send<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  spend: &Scalar,
  inputs: &[SpendableOutput],
  payments: &[(Address, u64)],
  change: Address,
  fee_per_byte: u64
) -> Result<Hash, TransactionError> {
  let fee = fee_per_byte * 2000; // TODO

  // TODO TX MAX SIZE

  let mut in_amount = 0;
  for input in inputs {
    in_amount += input.commitment.amount;
  }
  let mut out_amount = fee;
  for payment in payments {
    out_amount += payment.1
  }
  if in_amount < out_amount {
    Err(TransactionError::NotEnoughFunds(in_amount, out_amount))?;
  }

  // Handle outputs
  let mut payments = payments.to_vec();
  payments.push((change, in_amount - out_amount));
  let mut outputs = Vec::with_capacity(payments.len());
  for o in 0 .. payments.len() {
    outputs.push(Output::new(&mut *rng, payments[o], o)?);
  }

  let bp = bulletproofs::generate(
    outputs.iter().enumerate().map(|(o, output)| Commitment::new(output.mask, payments[o].1)).collect()
  )?;

  let mut extra = ExtraField(vec![
    SubField::TxPublicKey(PublicKey { point: outputs[0].R.compress() })
  ]);
  extra.0.push(SubField::AdditionalPublickKey(
    outputs[1 .. outputs.len()].iter().map(|output| PublicKey { point: output.R.compress() }).collect()
  ));

  // Handle inputs
  let mut signable = Vec::with_capacity(inputs.len());
  for input in inputs {
    let (m, mixins) = mixins::select(
      rpc.get_o_indexes(input.tx).await.map_err(|e| TransactionError::RpcError(e))?[input.o]
    );
    signable.push((
      spend + input.key_offset,
      SignableInput::new(
        key_image::generate(&(spend + input.key_offset)),
        mixins.clone(),
        rpc.get_ring(&mixins).await.map_err(|e| TransactionError::RpcError(e))?,
        m,
        input.commitment
      )?
    ));
  }

  let prefix = TransactionPrefix {
    version: VarInt(2),
    unlock_time: VarInt(0),
    inputs: signable.iter().map(|input| TxIn::ToKey {
      amount: VarInt(0),
      key_offsets: mixins::offset(&input.1.mixins).iter().map(|x| VarInt(*x)).collect(),
      k_image: KeyImage {
        image: Hash(input.1.image.compress().to_bytes())
      }
    }).collect(),
    outputs: outputs.iter().map(|output| TxOut {
      amount: VarInt(0),
      target: TxOutTarget::ToKey { key: PublicKey { point: output.dest.compress() } }
    }).collect(),
    extra
  };

  let base = RctSigBase {
    rct_type: RctType::Clsag,
    txn_fee: VarInt(fee),
    pseudo_outs: vec![],
    ecdh_info: outputs.iter().map(|output| EcdhInfo::Bulletproof { amount: output.amount }).collect(),
    out_pk: outputs.iter().enumerate().map(|(o, output)| CtKey {
      mask: Key {
        key: Commitment::new(output.mask, payments[o].1).calculate().compress().to_bytes()
      }
    }).collect()
  };

  let mut prunable = RctSigPrunable {
    range_sigs: vec![],
    bulletproofs: vec![bp],
    MGs: vec![],
    Clsags: vec![],
    pseudo_outs: vec![]
  };

  let mut tx = Transaction {
    prefix,
    signatures: vec![],
    rct_signatures: RctSig {
      sig: Some(base),
      p: Some(prunable.clone())
    }
  };

  let clsags = clsag::sign(
    rng,
    tx.signature_hash().expect("Couldn't get the signature hash").0,
    &signable,
    outputs.iter().map(|output| output.mask).sum()
  ).ok_or(TransactionError::NoInputs)?;
  prunable.Clsags = clsags.iter().map(|clsag| clsag.0.clone()).collect();
  prunable.pseudo_outs = clsags.iter().map(|clsag| Key { key: clsag.1.compress().to_bytes() }).collect();
  tx.rct_signatures.p = Some(prunable);

  rpc.publish_transaction(&tx).await.map_err(|e| TransactionError::InvalidTransaction(e))?;
  Ok(tx.hash())
}

use thiserror::Error;

use rand_core::{RngCore, CryptoRng};

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
    ringct::{Key, CtKey, EcdhInfo, Bulletproof, RctType, RctSigBase, RctSigPrunable, RctSig},
    address::Address
  }
};

#[cfg(feature = "multisig")]
use frost::FrostError;

use crate::{
  Commitment,
  random_scalar,
  hash, hash_to_scalar,
  key_image, bulletproofs, clsag,
  rpc::{Rpc, RpcError}
};
#[cfg(feature = "multisig")]
use crate::frost::MultisigError;

mod mixins;
#[cfg(feature = "multisig")]
mod multisig;

#[derive(Error, Debug)]
pub enum TransactionError {
  #[error("no inputs")]
  NoInputs,
  #[error("no outputs")]
  NoOutputs,
  #[error("too many outputs")]
  TooManyOutputs,
  #[error("not enough funds (in {0}, out {1})")]
  NotEnoughFunds(u64, u64),
  #[error("invalid address")]
  InvalidAddress,
  #[error("rpc error ({0})")]
  RpcError(RpcError),
  #[error("clsag error ({0})")]
  ClsagError(clsag::Error),
  #[error("invalid transaction ({0})")]
  InvalidTransaction(RpcError),
  #[cfg(feature = "multisig")]
  #[error("frost error {0}")]
  FrostError(FrostError),
  #[cfg(feature = "multisig")]
  #[error("multisig error {0}")]
  MultisigError(MultisigError)
}

#[derive(Clone, Debug)]
pub struct SpendableOutput {
  pub tx: Hash,
  pub o: usize,
  pub key: EdwardsPoint,
  pub key_offset: Scalar,
  pub commitment: Commitment
}

pub fn scan(tx: &Transaction, view: Scalar, spend: EdwardsPoint) -> Vec<SpendableOutput> {
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

        res.push(SpendableOutput { tx: tx.hash(), o, key: output_key, key_offset, commitment });
        break;
      }
    }
  }
  res
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
  pub fn new<R: RngCore + CryptoRng>(
    rng: &mut R,
    output: (Address, u64),
    o: usize
  ) -> Result<Output, TransactionError> {
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

async fn prepare_inputs<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  inputs: &[SpendableOutput],
  spend: &Scalar,
  tx: &mut Transaction
) -> Result<Vec<(Scalar, clsag::Input, EdwardsPoint)>, TransactionError> {
  // TODO sort inputs

  let mut signable = Vec::with_capacity(inputs.len());

  // Select mixins
  let mixins = mixins::select(
    rng,
    rpc,
    rpc.get_height().await.map_err(|e| TransactionError::RpcError(e))? - 10,
    inputs
  ).await.map_err(|e| TransactionError::RpcError(e))?;

  for (i, input) in inputs.iter().enumerate() {
    signable.push((
      spend + input.key_offset,
      clsag::Input::new(
        mixins[i].2.clone(),
        mixins[i].1,
        input.commitment
      ).map_err(|e| TransactionError::ClsagError(e))?,
      key_image::generate(&(spend + input.key_offset))
    ));

    tx.prefix.inputs.push(TxIn::ToKey {
      amount: VarInt(0),
      key_offsets: mixins[i].0.clone(),
      k_image: KeyImage { image: Hash(signable[i].2.compress().to_bytes()) }
    });
  }

  Ok(signable)
}

pub struct SignableTransaction {
  inputs: Vec<SpendableOutput>,
  payments: Vec<(Address, u64)>,
  change: Address,
  fee_per_byte: u64,

  fee: u64,
  outputs: Vec<Output>
}

impl SignableTransaction {
  pub fn new(
    inputs: Vec<SpendableOutput>,
    payments: Vec<(Address, u64)>,
    change: Address,
    fee_per_byte: u64
  ) -> Result<SignableTransaction, TransactionError> {
    if inputs.len() == 0 {
      Err(TransactionError::NoInputs)?;
    }
    if payments.len() == 0 {
      Err(TransactionError::NoOutputs)?;
    }

    Ok(
      SignableTransaction {
        inputs,
        payments,
        change,
        fee_per_byte,

        fee: 0,
        outputs: vec![]
      }
    )
  }

  fn prepare_outputs<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R
  ) -> Result<(Vec<Commitment>, Scalar), TransactionError> {
    self.fee = self.fee_per_byte * 2000; // TODO

    // TODO TX MAX SIZE

    // Make sure we have enough funds
    let in_amount = self.inputs.iter().map(|input| input.commitment.amount).sum();
    let out_amount = self.fee + self.payments.iter().map(|payment| payment.1).sum::<u64>();
    if in_amount < out_amount {
      Err(TransactionError::NotEnoughFunds(in_amount, out_amount))?;
    }

    // Add the change output
    let mut payments = self.payments.clone();
    payments.push((self.change, in_amount - out_amount));

    // TODO randomly sort outputs

    self.outputs.clear();
    self.outputs = Vec::with_capacity(payments.len());
    let mut commitments = Vec::with_capacity(payments.len());
    for o in 0 .. payments.len() {
      self.outputs.push(Output::new(rng, payments[o], o)?);
      commitments.push(Commitment::new(self.outputs[o].mask, payments[o].1));
    }

    Ok((commitments, self.outputs.iter().map(|output| output.mask).sum()))
  }

  fn prepare_transaction(
    &self,
    commitments: &[Commitment],
    bp: Bulletproof
  ) -> Transaction {
    // Create the TX extra
    let mut extra = ExtraField(vec![
      SubField::TxPublicKey(PublicKey { point: self.outputs[0].R.compress() })
    ]);
    extra.0.push(SubField::AdditionalPublickKey(
      self.outputs[1 .. self.outputs.len()].iter().map(|output| PublicKey { point: output.R.compress() }).collect()
    ));

    // Format it for monero-rs
    let mut mrs_outputs = Vec::with_capacity(self.outputs.len());
    let mut out_pk = Vec::with_capacity(self.outputs.len());
    let mut ecdh_info = Vec::with_capacity(self.outputs.len());
    for o in 0 .. self.outputs.len() {
      mrs_outputs.push(TxOut {
        amount: VarInt(0),
        target: TxOutTarget::ToKey { key: PublicKey { point: self.outputs[o].dest.compress() } }
      });
      out_pk.push(CtKey {
        mask: Key { key: commitments[o].calculate().compress().to_bytes() }
      });
      ecdh_info.push(EcdhInfo::Bulletproof { amount: self.outputs[o].amount });
    }

    Transaction {
      prefix: TransactionPrefix {
        version: VarInt(2),
        unlock_time: VarInt(0),
        inputs: vec![],
        outputs: mrs_outputs,
        extra
      },
      signatures: vec![],
      rct_signatures: RctSig {
        sig: Some(RctSigBase {
          rct_type: RctType::Clsag,
          txn_fee: VarInt(self.fee),
          pseudo_outs: vec![],
          ecdh_info,
          out_pk
        }),
        p: Some(RctSigPrunable {
          range_sigs: vec![],
          bulletproofs: vec![bp],
          MGs: vec![],
          Clsags: vec![],
          pseudo_outs: vec![]
        })
      }
    }
  }

  pub async fn sign<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    rpc: &Rpc,
    spend: &Scalar
  ) -> Result<Transaction, TransactionError> {
    let (commitments, mask_sum) = self.prepare_outputs(rng)?;
    let mut tx = self.prepare_transaction(&commitments, bulletproofs::generate(&commitments)?);

    let signable = prepare_inputs(rng, rpc, &self.inputs, spend, &mut tx).await?;

    let clsags = clsag::sign(
      rng,
      tx.signature_hash().expect("Couldn't get the signature hash").0,
      &signable,
      mask_sum
    ).unwrap(); // None if no inputs which new checks for
    let mut prunable = tx.rct_signatures.p.unwrap();
    prunable.Clsags = clsags.iter().map(|clsag| clsag.0.clone()).collect();
    prunable.pseudo_outs = clsags.iter().map(|clsag| Key { key: clsag.1.compress().to_bytes() }).collect();
    tx.rct_signatures.p = Some(prunable);
    Ok(tx)
  }
}

use thiserror::Error;

use rand_core::{RngCore, CryptoRng};
use rand::seq::SliceRandom;

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::EdwardsPoint
};

use monero::{
  consensus::Encodable,
  util::{key::PublicKey, address::Address},
  blockdata::transaction::SubField
};

#[cfg(feature = "multisig")]
use frost::FrostError;

use crate::{
  Commitment,
  random_scalar,
  generate_key_image,
  ringct::{
    clsag::{ClsagError, ClsagInput, Clsag},
    bulletproofs::Bulletproofs,
    RctBase, RctPrunable, RctSignatures
  },
  transaction::{Input, Output, Timelock, TransactionPrefix, Transaction},
  rpc::{Rpc, RpcError},
  wallet::{SpendableOutput, Decoys, key_image_sort, uniqueness, shared_key, commitment_mask, amount_encryption}
};
#[cfg(feature = "multisig")]
use crate::frost::MultisigError;

#[cfg(feature = "multisig")]
mod multisig;

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Debug)]
struct SendOutput {
  R: EdwardsPoint,
  dest: EdwardsPoint,
  mask: Scalar,
  amount: [u8; 8]
}

impl SendOutput {
  fn new<R: RngCore + CryptoRng>(
    rng: &mut R,
    unique: Option<[u8; 32]>,
    output: (Address, u64),
    o: usize
  ) -> Result<SendOutput, TransactionError> {
    let r = random_scalar(rng);
    let shared_key = shared_key(
      unique,
      r,
      &output.0.public_view.point.decompress().ok_or(TransactionError::InvalidAddress)?,
      o
    );

    Ok(
      SendOutput {
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


#[derive(Clone, Error, Debug)]
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
  ClsagError(ClsagError),
  #[error("invalid transaction ({0})")]
  InvalidTransaction(RpcError),
  #[cfg(feature = "multisig")]
  #[error("frost error {0}")]
  FrostError(FrostError),
  #[cfg(feature = "multisig")]
  #[error("multisig error {0}")]
  MultisigError(MultisigError)
}

async fn prepare_inputs<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  inputs: &[SpendableOutput],
  spend: &Scalar,
  tx: &mut Transaction
) -> Result<Vec<(Scalar, EdwardsPoint, ClsagInput)>, TransactionError> {
  let mut signable = Vec::with_capacity(inputs.len());

  // Select decoys
  let decoys = Decoys::select(
    rng,
    rpc,
    rpc.get_height().await.map_err(|e| TransactionError::RpcError(e))? - 10,
    inputs
  ).await.map_err(|e| TransactionError::RpcError(e))?;

  for (i, input) in inputs.iter().enumerate() {
    signable.push((
      spend + input.key_offset,
      generate_key_image(&(spend + input.key_offset)),
      ClsagInput::new(
        input.commitment,
        decoys[i].clone()
      ).map_err(|e| TransactionError::ClsagError(e))?
    ));

    tx.prefix.inputs.push(Input::ToKey {
      amount: 0,
      key_offsets: decoys[i].offsets.clone(),
      key_image: signable[i].1
    });
  }

  signable.sort_by(|x, y| x.1.compress().to_bytes().cmp(&y.1.compress().to_bytes()).reverse());
  tx.prefix.inputs.sort_by(|x, y| if let (
    Input::ToKey { key_image: x, ..},
    Input::ToKey { key_image: y, ..}
  ) = (x, y) {
    x.compress().to_bytes().cmp(&y.compress().to_bytes()).reverse()
  } else {
    panic!("Input wasn't ToKey")
  });

  Ok(signable)
}

#[derive(Clone, PartialEq, Debug)]
pub struct SignableTransaction {
  inputs: Vec<SpendableOutput>,
  payments: Vec<(Address, u64)>,
  change: Address,
  fee_per_byte: u64,

  fee: u64,
  outputs: Vec<SendOutput>
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
    rng: &mut R,
    uniqueness: [u8; 32]
  ) -> Result<(Vec<Commitment>, Scalar), TransactionError> {
    self.fee = self.fee_per_byte * 2000; // TODO

    // TODO TX MAX SIZE

    // Make sure we have enough funds
    let in_amount = self.inputs.iter().map(|input| input.commitment.amount).sum();
    let out_amount = self.fee + self.payments.iter().map(|payment| payment.1).sum::<u64>();
    if in_amount < out_amount {
      Err(TransactionError::NotEnoughFunds(in_amount, out_amount))?;
    }

    let mut temp_outputs = Vec::with_capacity(self.payments.len() + 1);
    // Add the payments to the outputs
    for payment in &self.payments {
      temp_outputs.push((None, (payment.0, payment.1)));
    }
    temp_outputs.push((Some(uniqueness), (self.change, in_amount - out_amount)));

    // Shuffle the outputs
    temp_outputs.shuffle(rng);

    // Actually create the outputs
    self.outputs = Vec::with_capacity(temp_outputs.len());
    let mut commitments = Vec::with_capacity(temp_outputs.len());
    let mut mask_sum = Scalar::zero();
    for (o, output) in temp_outputs.iter().enumerate() {
      self.outputs.push(SendOutput::new(rng, output.0, output.1, o)?);
      commitments.push(Commitment::new(self.outputs[o].mask, output.1.1));
      mask_sum += self.outputs[o].mask;
    }

    Ok((commitments, mask_sum))
  }

  fn prepare_transaction(
    &self,
    commitments: &[Commitment],
    bp: Bulletproofs
  ) -> Transaction {
    // Create the TX extra
    let mut extra = vec![];
    SubField::TxPublicKey(
      PublicKey { point: self.outputs[0].R.compress() }
    ).consensus_encode(&mut extra).unwrap();
    SubField::AdditionalPublickKey(
      self.outputs[1 ..].iter().map(|output| PublicKey { point: output.R.compress() }).collect()
    ).consensus_encode(&mut extra).unwrap();

    // Format it for monero-rs
    let mut tx_outputs = Vec::with_capacity(self.outputs.len());
    let mut ecdh_info = Vec::with_capacity(self.outputs.len());
    for o in 0 .. self.outputs.len() {
      tx_outputs.push(Output {
        amount: 0,
        key: self.outputs[o].dest,
        tag: None
      });
      ecdh_info.push(self.outputs[o].amount);
    }

    Transaction {
      prefix: TransactionPrefix {
        version: 2,
        timelock: Timelock::None,
        inputs: vec![],
        outputs: tx_outputs,
        extra
      },
      rct_signatures: RctSignatures {
        base: RctBase {
          fee: self.fee,
          ecdh_info,
          commitments: commitments.iter().map(|commitment| commitment.calculate()).collect()
        },
        prunable: RctPrunable::Clsag {
          bulletproofs: vec![bp],
          clsags: vec![],
          pseudo_outs: vec![]
        }
      }
    }
  }

  pub async fn sign<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    rpc: &Rpc,
    spend: &Scalar
  ) -> Result<Transaction, TransactionError> {
    let mut images = Vec::with_capacity(self.inputs.len());
    for input in &self.inputs {
      images.push(generate_key_image(&(spend + input.key_offset)));
    }
    images.sort_by(key_image_sort);

    let (commitments, mask_sum) = self.prepare_outputs(
      rng,
      uniqueness(
        &images.iter().map(|image| Input::ToKey {
          amount: 0,
          key_offsets: vec![],
          key_image: *image
        }).collect::<Vec<_>>()
      )
    )?;

    let mut tx = self.prepare_transaction(&commitments, Bulletproofs::new(rng, &commitments)?);

    let signable = prepare_inputs(rng, rpc, &self.inputs, spend, &mut tx).await?;

    let clsag_pairs = Clsag::sign(rng, &signable, mask_sum, tx.signature_hash());
    match tx.rct_signatures.prunable {
      RctPrunable::Null => panic!("Signing for RctPrunable::Null"),
      RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. } => {
        clsags.append(&mut clsag_pairs.iter().map(|clsag| clsag.0.clone()).collect::<Vec<_>>());
        pseudo_outs.append(&mut clsag_pairs.iter().map(|clsag| clsag.1.clone()).collect::<Vec<_>>());
      }
    }
    Ok(tx)
  }
}

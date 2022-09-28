use thiserror::Error;

use rand_core::{RngCore, CryptoRng};
use rand::seq::SliceRandom;

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar, edwards::EdwardsPoint};

#[cfg(feature = "multisig")]
use frost::FrostError;

use crate::{
  Protocol, Commitment, random_scalar,
  ringct::{
    generate_key_image,
    clsag::{ClsagError, ClsagInput, Clsag},
    bulletproofs::{MAX_OUTPUTS, Bulletproofs},
    RctBase, RctPrunable, RctSignatures,
  },
  transaction::{Input, Output, Timelock, TransactionPrefix, Transaction},
  rpc::{Rpc, RpcError},
  wallet::{
    address::Address, SpendableOutput, Decoys, PaymentId, ExtraField, Extra, key_image_sort,
    uniqueness, shared_key, commitment_mask, amount_encryption,
  },
};

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use multisig::TransactionMachine;

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
struct SendOutput {
  R: EdwardsPoint,
  view_tag: u8,
  dest: EdwardsPoint,
  commitment: Commitment,
  amount: [u8; 8],
}

impl SendOutput {
  fn new<R: RngCore + CryptoRng>(
    rng: &mut R,
    unique: [u8; 32],
    output: (usize, (Address, u64)),
  ) -> (SendOutput, Option<[u8; 8]>) {
    let o = output.0;
    let output = output.1;

    let r = random_scalar(rng);
    let (view_tag, shared_key, payment_id_xor) =
      shared_key(Some(unique).filter(|_| output.0.meta.kind.guaranteed()), &r, &output.0.view, o);

    (
      SendOutput {
        R: if !output.0.meta.kind.subaddress() {
          &r * &ED25519_BASEPOINT_TABLE
        } else {
          r * output.0.spend
        },
        view_tag,
        dest: ((&shared_key * &ED25519_BASEPOINT_TABLE) + output.0.spend),
        commitment: Commitment::new(commitment_mask(shared_key), output.1),
        amount: amount_encryption(output.1, shared_key),
      },
      output
        .0
        .payment_id()
        .map(|id| (u64::from_le_bytes(id) ^ u64::from_le_bytes(payment_id_xor)).to_le_bytes()),
    )
  }
}

#[derive(Clone, Error, Debug)]
pub enum TransactionError {
  #[error("multiple addresses with payment IDs")]
  MultiplePaymentIds,
  #[error("no inputs")]
  NoInputs,
  #[error("no outputs")]
  NoOutputs,
  #[error("only one output and no change address")]
  NoChange,
  #[error("too many outputs")]
  TooManyOutputs,
  #[error("too much data")]
  TooMuchData,
  #[error("not enough funds (in {0}, out {1})")]
  NotEnoughFunds(u64, u64),
  #[error("wrong spend private key")]
  WrongPrivateKey,
  #[error("rpc error ({0})")]
  RpcError(RpcError),
  #[error("clsag error ({0})")]
  ClsagError(ClsagError),
  #[error("invalid transaction ({0})")]
  InvalidTransaction(RpcError),
  #[cfg(feature = "multisig")]
  #[error("frost error {0}")]
  FrostError(FrostError),
}

async fn prepare_inputs<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  ring_len: usize,
  inputs: &[SpendableOutput],
  spend: &Scalar,
  tx: &mut Transaction,
) -> Result<Vec<(Scalar, EdwardsPoint, ClsagInput)>, TransactionError> {
  let mut signable = Vec::with_capacity(inputs.len());

  // Select decoys
  let decoys = Decoys::select(
    rng,
    rpc,
    ring_len,
    rpc.get_height().await.map_err(TransactionError::RpcError)? - 10,
    inputs,
  )
  .await
  .map_err(TransactionError::RpcError)?;

  for (i, input) in inputs.iter().enumerate() {
    signable.push((
      spend + input.key_offset(),
      generate_key_image(spend + input.key_offset()),
      ClsagInput::new(input.commitment().clone(), decoys[i].clone())
        .map_err(TransactionError::ClsagError)?,
    ));

    tx.prefix.inputs.push(Input::ToKey {
      amount: 0,
      key_offsets: decoys[i].offsets.clone(),
      key_image: signable[i].1,
    });
  }

  signable.sort_by(|x, y| x.1.compress().to_bytes().cmp(&y.1.compress().to_bytes()).reverse());
  tx.prefix.inputs.sort_by(|x, y| {
    if let (Input::ToKey { key_image: x, .. }, Input::ToKey { key_image: y, .. }) = (x, y) {
      x.compress().to_bytes().cmp(&y.compress().to_bytes()).reverse()
    } else {
      panic!("Input wasn't ToKey")
    }
  });

  Ok(signable)
}

/// Fee struct, defined as a per-unit cost and a mask for rounding purposes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fee {
  pub per_weight: u64,
  pub mask: u64,
}

impl Fee {
  pub fn calculate(&self, weight: usize) -> u64 {
    ((((self.per_weight * u64::try_from(weight).unwrap()) - 1) / self.mask) + 1) * self.mask
  }
}

/// A signable transaction, either in a single-signer or multisig context.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SignableTransaction {
  protocol: Protocol,
  inputs: Vec<SpendableOutput>,
  payments: Vec<(Address, u64)>,
  data: Option<Vec<u8>>,
  fee: u64,
}

impl SignableTransaction {
  /// Create a signable transaction. If the change address is specified, leftover funds will be
  /// sent to it. If the change address isn't specified, up to 16 outputs may be specified, using
  /// any leftover funds as a bonus to the fee. The optional data field will be embedded in TX
  /// extra.
  pub fn new(
    protocol: Protocol,
    inputs: Vec<SpendableOutput>,
    mut payments: Vec<(Address, u64)>,
    change_address: Option<Address>,
    data: Option<Vec<u8>>,
    fee_rate: Fee,
  ) -> Result<SignableTransaction, TransactionError> {
    // Make sure there's only one payment ID
    {
      let mut payment_ids = 0;
      let mut count = |addr: Address| {
        if addr.payment_id().is_some() {
          payment_ids += 1
        }
      };
      for payment in &payments {
        count(payment.0);
      }
      if let Some(change) = change_address {
        count(change);
      }
      if payment_ids > 1 {
        Err(TransactionError::MultiplePaymentIds)?;
      }
    }

    if inputs.is_empty() {
      Err(TransactionError::NoInputs)?;
    }
    if payments.is_empty() {
      Err(TransactionError::NoOutputs)?;
    }

    if data.as_ref().map(|v| v.len()).unwrap_or(0) > 255 {
      Err(TransactionError::TooMuchData)?;
    }

    // TODO TX MAX SIZE

    // If we don't have two outputs, as required by Monero, add a second
    let mut change = payments.len() == 1;
    if change && change_address.is_none() {
      Err(TransactionError::NoChange)?;
    }
    let outputs = payments.len() + usize::from(change);

    // Calculate the extra length
    let extra = Extra::fee_weight(outputs, data.as_ref());

    // Calculate the fee.
    let mut fee =
      fee_rate.calculate(Transaction::fee_weight(protocol, inputs.len(), outputs, extra));

    // Make sure we have enough funds
    let in_amount = inputs.iter().map(|input| input.commitment().amount).sum::<u64>();
    let mut out_amount = payments.iter().map(|payment| payment.1).sum::<u64>() + fee;
    if in_amount < out_amount {
      Err(TransactionError::NotEnoughFunds(in_amount, out_amount))?;
    }

    // If we have yet to add a change output, do so if it's economically viable
    if (!change) && change_address.is_some() && (in_amount != out_amount) {
      // Check even with the new fee, there's remaining funds
      let change_fee =
        fee_rate.calculate(Transaction::fee_weight(protocol, inputs.len(), outputs + 1, extra)) -
          fee;
      if (out_amount + change_fee) < in_amount {
        change = true;
        out_amount += change_fee;
        fee += change_fee;
      }
    }

    if change {
      payments.push((change_address.unwrap(), in_amount - out_amount));
    }

    if payments.len() > MAX_OUTPUTS {
      Err(TransactionError::TooManyOutputs)?;
    }

    Ok(SignableTransaction { protocol, inputs, payments, data, fee })
  }

  fn prepare_transaction<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    uniqueness: [u8; 32],
  ) -> (Transaction, Scalar) {
    // Shuffle the payments
    self.payments.shuffle(rng);

    // Actually create the outputs
    let mut outputs = Vec::with_capacity(self.payments.len());
    let mut id = None;
    for payment in self.payments.drain(..).enumerate() {
      let (output, payment_id) = SendOutput::new(rng, uniqueness, payment);
      outputs.push(output);
      id = id.or(payment_id);
    }

    // Include a random payment ID if we don't actually have one
    // It prevents transactions from leaking if they're sending to integrated addresses or not
    let id = if let Some(id) = id {
      id
    } else {
      let mut id = [0; 8];
      rng.fill_bytes(&mut id);
      id
    };

    let commitments = outputs.iter().map(|output| output.commitment.clone()).collect::<Vec<_>>();
    let sum = commitments.iter().map(|commitment| commitment.mask).sum();

    // Safe due to the constructor checking MAX_OUTPUTS
    let bp = Bulletproofs::prove(rng, &commitments, self.protocol.bp_plus()).unwrap();

    // Create the TX extra
    let extra = {
      let mut extra = Extra::new(outputs.iter().map(|output| output.R).collect());

      let mut id_vec = Vec::with_capacity(1 + 8);
      PaymentId::Encrypted(id).serialize(&mut id_vec).unwrap();
      extra.push(ExtraField::Nonce(id_vec));

      // Include data if present
      if let Some(data) = self.data.take() {
        extra.push(ExtraField::Nonce(data));
      }

      let mut serialized = Vec::with_capacity(Extra::fee_weight(outputs.len(), self.data.as_ref()));
      extra.serialize(&mut serialized).unwrap();
      serialized
    };

    let mut tx_outputs = Vec::with_capacity(outputs.len());
    let mut ecdh_info = Vec::with_capacity(outputs.len());
    for output in &outputs {
      tx_outputs.push(Output {
        amount: 0,
        key: output.dest.compress(),
        view_tag: Some(output.view_tag).filter(|_| matches!(self.protocol, Protocol::v16)),
      });
      ecdh_info.push(output.amount);
    }

    (
      Transaction {
        prefix: TransactionPrefix {
          version: 2,
          timelock: Timelock::None,
          inputs: vec![],
          outputs: tx_outputs,
          extra,
        },
        signatures: vec![],
        rct_signatures: RctSignatures {
          base: RctBase {
            fee: self.fee,
            ecdh_info,
            commitments: commitments.iter().map(|commitment| commitment.calculate()).collect(),
          },
          prunable: RctPrunable::Clsag {
            bulletproofs: vec![bp],
            clsags: vec![],
            pseudo_outs: vec![],
          },
        },
      },
      sum,
    )
  }

  /// Sign this transaction.
  pub async fn sign<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    rpc: &Rpc,
    spend: &Scalar,
  ) -> Result<Transaction, TransactionError> {
    let mut images = Vec::with_capacity(self.inputs.len());
    for input in &self.inputs {
      let mut offset = spend + input.key_offset();
      if (&offset * &ED25519_BASEPOINT_TABLE) != input.key() {
        Err(TransactionError::WrongPrivateKey)?;
      }

      images.push(generate_key_image(offset));
      offset.zeroize();
    }
    images.sort_by(key_image_sort);

    let (mut tx, mask_sum) = self.prepare_transaction(
      rng,
      uniqueness(
        &images
          .iter()
          .map(|image| Input::ToKey { amount: 0, key_offsets: vec![], key_image: *image })
          .collect::<Vec<_>>(),
      ),
    );

    let signable =
      prepare_inputs(rng, rpc, self.protocol.ring_len(), &self.inputs, spend, &mut tx).await?;

    let clsag_pairs = Clsag::sign(rng, signable, mask_sum, tx.signature_hash());
    match tx.rct_signatures.prunable {
      RctPrunable::Null => panic!("Signing for RctPrunable::Null"),
      RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. } => {
        clsags.append(&mut clsag_pairs.iter().map(|clsag| clsag.0.clone()).collect::<Vec<_>>());
        pseudo_outs.append(&mut clsag_pairs.iter().map(|clsag| clsag.1).collect::<Vec<_>>());
      }
    }
    Ok(tx)
  }
}

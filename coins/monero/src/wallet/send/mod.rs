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
  util::{key::PublicKey, address::{AddressType, Address}},
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
    bulletproofs::{MAX_OUTPUTS, Bulletproofs},
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
#[cfg(feature = "multisig")]
pub use multisig::TransactionMachine;

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Debug)]
struct SendOutput {
  R: EdwardsPoint,
  dest: EdwardsPoint,
  commitment: Commitment,
  amount: [u8; 8]
}

impl SendOutput {
  fn new<R: RngCore + CryptoRng>(
    rng: &mut R,
    unique: [u8; 32],
    output: (Address, u64, bool),
    o: usize
  ) -> SendOutput {
    let r = random_scalar(rng);
    let shared_key = shared_key(
      Some(unique).filter(|_| output.2),
      r,
      &output.0.public_view.point.decompress().expect("SendOutput::new requires valid addresses"),
      o
    );

    let spend = output.0.public_spend.point.decompress().expect("SendOutput::new requires valid addresses");
    SendOutput {
      R: match output.0.addr_type {
        AddressType::Standard => &r * &ED25519_BASEPOINT_TABLE,
        AddressType::SubAddress => &r * spend,
        AddressType::Integrated(_) => panic!("SendOutput::new doesn't support Integrated addresses")
      },
      dest: ((&shared_key * &ED25519_BASEPOINT_TABLE) + spend),
      commitment: Commitment::new(commitment_mask(shared_key), output.1),
      amount: amount_encryption(output.1, shared_key)
    }
  }
}

#[derive(Clone, Error, Debug)]
pub enum TransactionError {
  #[error("invalid address")]
  InvalidAddress,
  #[error("no inputs")]
  NoInputs,
  #[error("no outputs")]
  NoOutputs,
  #[error("only one output and no change address")]
  NoChange,
  #[error("too many outputs")]
  TooManyOutputs,
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fee {
  pub per_weight: u64,
  pub mask: u64
}

impl Fee {
  pub fn calculate(&self, weight: usize) -> u64 {
    ((((self.per_weight * u64::try_from(weight).unwrap()) - 1) / self.mask) + 1) * self.mask
  }
}

#[derive(Clone, PartialEq, Debug)]
pub struct SignableTransaction {
  inputs: Vec<SpendableOutput>,
  payments: Vec<(Address, u64, bool)>,
  outputs: Vec<SendOutput>,
  fee: u64
}

impl SignableTransaction {
  pub fn new(
    inputs: Vec<SpendableOutput>,
    payments: Vec<(Address, u64)>,
    change_address: Option<Address>,
    fee_rate: Fee
  ) -> Result<SignableTransaction, TransactionError> {
    // Make sure all addresses are valid
    let test = |addr: Address| {
      if !(
        addr.public_view.point.decompress().is_some() &&
        addr.public_spend.point.decompress().is_some()
      ) {
        Err(TransactionError::InvalidAddress)?;
      }

      match addr.addr_type {
        AddressType::Standard => Ok(()),
        AddressType::Integrated(..) => Err(TransactionError::InvalidAddress),
        AddressType::SubAddress => Ok(())
      }
    };

    for payment in &payments {
      test(payment.0)?;
    }
    if let Some(change) = change_address {
      test(change)?;
    }

    if inputs.len() == 0 {
      Err(TransactionError::NoInputs)?;
    }
    if payments.len() == 0 {
      Err(TransactionError::NoOutputs)?;
    }

    // TODO TX MAX SIZE

    // If we don't have two outputs, as required by Monero, add a second
    let mut change = payments.len() == 1;
    if change && change_address.is_none() {
      Err(TransactionError::NoChange)?;
    }
    let mut outputs = payments.len() + (if change { 1 } else { 0 });

    // Calculate the fee.
    let extra = 0;
    let mut fee = fee_rate.calculate(Transaction::fee_weight(inputs.len(), outputs, extra));

    // Make sure we have enough funds
    let in_amount = inputs.iter().map(|input| input.commitment.amount).sum::<u64>();
    let mut out_amount = payments.iter().map(|payment| payment.1).sum::<u64>() + fee;
    if in_amount < out_amount {
      Err(TransactionError::NotEnoughFunds(in_amount, out_amount))?;
    }

    // If we have yet to add a change output, do so if it's economically viable
    if (!change) && change_address.is_some() && (in_amount != out_amount) {
      // Check even with the new fee, there's remaining funds
      let change_fee = fee_rate.calculate(Transaction::fee_weight(inputs.len(), outputs + 1, extra)) - fee;
      if (out_amount + change_fee) < in_amount {
        change = true;
        outputs += 1;
        out_amount += change_fee;
        fee += change_fee;
      }
    }

    if outputs > MAX_OUTPUTS {
      Err(TransactionError::TooManyOutputs)?;
    }

    let mut payments = payments.iter().map(|(address, amount)| (*address, *amount, false)).collect::<Vec<_>>();
    if change {
      // Always use a unique key image for the change output
      // TODO: Make this a config option
      payments.push((change_address.unwrap(), in_amount - out_amount, true));
    }

    Ok(
      SignableTransaction {
        inputs,
        payments,
        outputs: vec![],
        fee
      }
    )
  }

  fn prepare_outputs<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    uniqueness: [u8; 32]
  ) -> (Vec<Commitment>, Scalar) {
    // Shuffle the payments
    self.payments.shuffle(rng);

    // Actually create the outputs
    self.outputs = Vec::with_capacity(self.payments.len() + 1);
    for (o, output) in self.payments.iter().enumerate() {
      self.outputs.push(SendOutput::new(rng, uniqueness, *output, o));
    }

    let commitments = self.outputs.iter().map(|output| output.commitment).collect::<Vec<_>>();
    let sum = commitments.iter().map(|commitment| commitment.mask).sum();
    (commitments, sum)
  }

  fn prepare_transaction(
    &self,
    commitments: &[Commitment],
    bp: Bulletproofs
  ) -> Transaction {
    // Create the TX extra
    // TODO: Review this for canonicity with Monero
    let mut extra = vec![];
    SubField::TxPublicKey(
      PublicKey { point: self.outputs[0].R.compress() }
    ).consensus_encode(&mut extra).unwrap();
    SubField::AdditionalPublickKey(
      self.outputs[1 ..].iter().map(|output| PublicKey { point: output.R.compress() }).collect()
    ).consensus_encode(&mut extra).unwrap();

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
      let offset = spend + input.key_offset;
      if (&offset * &ED25519_BASEPOINT_TABLE) != input.key {
        Err(TransactionError::WrongPrivateKey)?;
      }

      images.push(generate_key_image(&offset));
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
    );

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

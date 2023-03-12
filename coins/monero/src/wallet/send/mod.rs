use core::{ops::Deref, fmt};

use thiserror::Error;

use rand_core::{RngCore, CryptoRng};
use rand::seq::SliceRandom;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use group::Group;
use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE},
  scalar::Scalar,
  edwards::EdwardsPoint,
};
use dalek_ff_group as dfg;

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
    address::{Network, AddressSpec, MoneroAddress},
    ViewPair, SpendableOutput, Decoys, PaymentId, ExtraField, Extra, key_image_sort, uniqueness,
    shared_key, commitment_mask, amount_encryption,
    extra::{ARBITRARY_DATA_MARKER, MAX_ARBITRARY_DATA_SIZE},
  },
};

mod builder;
pub use builder::SignableTransactionBuilder;

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
  #[allow(non_snake_case)]
  fn internal(
    unique: [u8; 32],
    output: (usize, (MoneroAddress, u64)),
    ecdh: EdwardsPoint,
    R: EdwardsPoint,
  ) -> (SendOutput, Option<[u8; 8]>) {
    let o = output.0;
    let output = output.1;

    let (view_tag, shared_key, payment_id_xor) =
      shared_key(Some(unique).filter(|_| output.0.is_guaranteed()), ecdh, o);

    (
      SendOutput {
        R,
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

  fn new(
    r: &Zeroizing<Scalar>,
    unique: [u8; 32],
    output: (usize, (MoneroAddress, u64)),
  ) -> (SendOutput, Option<[u8; 8]>) {
    let address = output.1 .0;
    SendOutput::internal(
      unique,
      output,
      r.deref() * address.view,
      if !address.is_subaddress() {
        r.deref() * &ED25519_BASEPOINT_TABLE
      } else {
        r.deref() * address.spend
      },
    )
  }

  fn change(
    ecdh: EdwardsPoint,
    unique: [u8; 32],
    output: (usize, (MoneroAddress, u64)),
  ) -> (SendOutput, Option<[u8; 8]>) {
    SendOutput::internal(unique, output, ecdh, ED25519_BASEPOINT_POINT)
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Error)]
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
  #[error("too many inputs/too much arbitrary data")]
  TooLargeTransaction,
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
  spend: &Zeroizing<Scalar>,
  tx: &mut Transaction,
) -> Result<Vec<(Zeroizing<Scalar>, EdwardsPoint, ClsagInput)>, TransactionError> {
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
    let input_spend = Zeroizing::new(input.key_offset() + spend.deref());
    let image = generate_key_image(&input_spend);
    signable.push((
      input_spend,
      image,
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
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
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
  payments: Vec<InternalPayment>,
  data: Vec<Vec<u8>>,
  fee: u64,
}

/// Specification for a change output.
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct Change {
  address: MoneroAddress,
  view: Option<Zeroizing<Scalar>>,
}

impl fmt::Debug for Change {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.debug_struct("Change").field("address", &self.address).finish_non_exhaustive()
  }
}

impl Change {
  /// Create a change output specification from a ViewPair, as needed to maintain privacy.
  pub fn new(view: &ViewPair, guaranteed: bool) -> Change {
    Change {
      address: view.address(
        Network::Mainnet,
        if !guaranteed {
          AddressSpec::Standard
        } else {
          AddressSpec::Featured { subaddress: None, payment_id: None, guaranteed: true }
        },
      ),
      view: Some(view.view.clone()),
    }
  }

  /// Create a fingerprintable change output specification which will harm privacy. Only use this
  /// if you know what you're doing.
  pub fn fingerprintable(address: MoneroAddress) -> Change {
    Change { address, view: None }
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) enum InternalPayment {
  Payment((MoneroAddress, u64)),
  Change(Change, u64),
}

impl SignableTransaction {
  /// Create a signable transaction.
  ///
  /// Up to 16 outputs may be present, including the change output.
  ///
  /// If the change address is specified, leftover funds will be sent to it.
  ///
  /// Each chunk of data must not exceed MAX_ARBITRARY_DATA_SIZE.
  pub fn new(
    protocol: Protocol,
    inputs: Vec<SpendableOutput>,
    mut payments: Vec<(MoneroAddress, u64)>,
    change_address: Option<Change>,
    data: Vec<Vec<u8>>,
    fee_rate: Fee,
  ) -> Result<SignableTransaction, TransactionError> {
    // Make sure there's only one payment ID
    let mut has_payment_id = {
      let mut payment_ids = 0;
      let mut count = |addr: MoneroAddress| {
        if addr.payment_id().is_some() {
          payment_ids += 1
        }
      };
      for payment in &payments {
        count(payment.0);
      }
      if let Some(change) = change_address.as_ref() {
        count(change.address);
      }
      if payment_ids > 1 {
        Err(TransactionError::MultiplePaymentIds)?;
      }
      payment_ids == 1
    };

    if inputs.is_empty() {
      Err(TransactionError::NoInputs)?;
    }
    if payments.is_empty() {
      Err(TransactionError::NoOutputs)?;
    }

    for part in &data {
      if part.len() > MAX_ARBITRARY_DATA_SIZE {
        Err(TransactionError::TooMuchData)?;
      }
    }

    // If we don't have two outputs, as required by Monero, error
    if (payments.len() == 1) && change_address.is_none() {
      Err(TransactionError::NoChange)?;
    }
    let outputs = payments.len() + usize::from(change_address.is_some());
    // Add a dummy payment ID if there's only 2 payments
    has_payment_id |= outputs == 2;

    // Calculate the extra length
    let extra = Extra::fee_weight(outputs, has_payment_id, data.as_ref());

    // This is a extremely heavy fee weight estimation which can only be trusted for two things
    // 1) Ensuring we have enough for whatever fee we end up using
    // 2) Ensuring we aren't over the max size
    let estimated_tx_size = Transaction::fee_weight(protocol, inputs.len(), outputs, extra);

    // The actual limit is half the block size, and for the minimum block size of 300k, that'd be
    // 150k
    // wallet2 will only create transactions up to 100k bytes however
    const MAX_TX_SIZE: usize = 100_000;

    // This uses the weight (estimated_tx_size) despite the BP clawback
    // The clawback *increases* the weight, so this will over-estimate, yet it's still safe
    if estimated_tx_size >= MAX_TX_SIZE {
      Err(TransactionError::TooLargeTransaction)?;
    }

    // Calculate the fee.
    let fee = fee_rate.calculate(estimated_tx_size);

    // Make sure we have enough funds
    let in_amount = inputs.iter().map(|input| input.commitment().amount).sum::<u64>();
    let out_amount = payments.iter().map(|payment| payment.1).sum::<u64>() + fee;
    if in_amount < out_amount {
      Err(TransactionError::NotEnoughFunds(in_amount, out_amount))?;
    }

    if outputs > MAX_OUTPUTS {
      Err(TransactionError::TooManyOutputs)?;
    }

    let mut payments = payments.drain(..).map(InternalPayment::Payment).collect::<Vec<_>>();
    if let Some(change) = change_address {
      payments.push(InternalPayment::Change(change, in_amount - out_amount));
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

    // Used for all non-subaddress outputs, or if there's only one subaddress output and a change
    let tx_key = Zeroizing::new(random_scalar(rng));
    let mut tx_public_key = tx_key.deref() * &ED25519_BASEPOINT_TABLE;

    // If any of these outputs are to a subaddress, we need keys distinct to them
    // The only time this *does not* force having additional keys is when the only other output
    // is a change output we have the view key for, enabling rewriting rA to aR
    let mut has_change_view = false;
    let subaddresses = self
      .payments
      .iter()
      .filter(|payment| match *payment {
        InternalPayment::Payment(payment) => payment.0.is_subaddress(),
        InternalPayment::Change(change, _) => {
          if change.view.is_some() {
            has_change_view = true;
            // It should not be possible to construct a change specification to a subaddress with a
            // view key
            debug_assert!(!change.address.is_subaddress());
          }
          change.address.is_subaddress()
        }
      })
      .count() !=
      0;

    // We need additional keys if we have any subaddresses
    let mut additional = subaddresses;
    // Unless the above change view key path is taken
    if (self.payments.len() == 2) && has_change_view {
      additional = false;
    }
    let modified_change_ecdh = subaddresses && (!additional);

    // If we're using the aR rewrite, update tx_public_key from rG to rB
    if modified_change_ecdh {
      for payment in &self.payments {
        match payment {
          InternalPayment::Payment(payment) => {
            // This should be the only payment and it should be a subaddress
            debug_assert!(payment.0.is_subaddress());
            tx_public_key = tx_key.deref() * payment.0.spend;
          }
          InternalPayment::Change(_, _) => {}
        }
      }
      debug_assert!(tx_public_key != (tx_key.deref() * &ED25519_BASEPOINT_TABLE));
    }

    // Actually create the outputs
    let mut outputs = Vec::with_capacity(self.payments.len());
    let mut id = None;
    for (o, mut payment) in self.payments.drain(..).enumerate() {
      // Downcast the change output to a payment output if it doesn't require special handling
      // regarding it's view key
      payment = if !modified_change_ecdh {
        if let InternalPayment::Change(change, amount) = &payment {
          InternalPayment::Payment((change.address, *amount))
        } else {
          payment
        }
      } else {
        payment
      };

      let (output, payment_id) = match payment {
        InternalPayment::Payment(payment) => {
          // If this is a subaddress, generate a dedicated r. Else, reuse the TX key
          let dedicated = Zeroizing::new(random_scalar(&mut *rng));
          let use_dedicated = additional && payment.0.is_subaddress();
          let r = if use_dedicated { &dedicated } else { &tx_key };

          let (mut output, payment_id) = SendOutput::new(r, uniqueness, (o, payment));
          if modified_change_ecdh {
            debug_assert_eq!(tx_public_key, output.R);
          }
          // If this used tx_key, randomize its R
          if !use_dedicated {
            output.R = dfg::EdwardsPoint::random(&mut *rng).0;
          }
          (output, payment_id)
        }
        InternalPayment::Change(change, amount) => {
          // Instead of rA, use Ra, where R is r * subaddress_spend_key
          // change.view must be Some as if it's None, this payment would've been downcast
          let ecdh = tx_public_key * change.view.unwrap().deref();
          SendOutput::change(ecdh, uniqueness, (o, (change.address, amount)))
        }
      };

      outputs.push(output);
      id = id.or(payment_id);
    }

    // Include a random payment ID if we don't actually have one
    // It prevents transactions from leaking if they're sending to integrated addresses or not
    // Only do this if we only have two outputs though, as Monero won't add a dummy if there's
    // more than two outputs
    if outputs.len() <= 2 {
      let mut rand = [0; 8];
      rng.fill_bytes(&mut rand);
      id = id.or(Some(rand));
    }

    let commitments = outputs.iter().map(|output| output.commitment.clone()).collect::<Vec<_>>();
    let sum = commitments.iter().map(|commitment| commitment.mask).sum();

    // Safe due to the constructor checking MAX_OUTPUTS
    let bp = Bulletproofs::prove(rng, &commitments, self.protocol.bp_plus()).unwrap();

    // Create the TX extra
    let extra = {
      let mut extra = Extra::new(
        tx_public_key,
        if additional { outputs.iter().map(|output| output.R).collect() } else { vec![] },
      );

      if let Some(id) = id {
        let mut id_vec = Vec::with_capacity(1 + 8);
        PaymentId::Encrypted(id).write(&mut id_vec).unwrap();
        extra.push(ExtraField::Nonce(id_vec));
      }

      // Include data if present
      for part in self.data.drain(..) {
        let mut arb = vec![ARBITRARY_DATA_MARKER];
        arb.extend(part);
        extra.push(ExtraField::Nonce(arb));
      }

      let mut serialized =
        Vec::with_capacity(Extra::fee_weight(outputs.len(), id.is_some(), self.data.as_ref()));
      extra.write(&mut serialized).unwrap();
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
    mut self,
    rng: &mut R,
    rpc: &Rpc,
    spend: &Zeroizing<Scalar>,
  ) -> Result<Transaction, TransactionError> {
    let mut images = Vec::with_capacity(self.inputs.len());
    for input in &self.inputs {
      let mut offset = Zeroizing::new(spend.deref() + input.key_offset());
      if (offset.deref() * &ED25519_BASEPOINT_TABLE) != input.key() {
        Err(TransactionError::WrongPrivateKey)?;
      }

      images.push(generate_key_image(&offset));
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

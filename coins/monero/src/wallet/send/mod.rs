use core::{ops::Deref, fmt};
use std::io;

use thiserror::Error;

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;
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
  Protocol, Commitment, hash, random_scalar,
  serialize::{
    read_byte, read_bytes, read_u64, read_scalar, read_point, read_vec, write_byte, write_scalar,
    write_point, write_raw_vec, write_vec,
  },
  ringct::{
    generate_key_image,
    clsag::{ClsagError, ClsagInput, Clsag},
    bulletproofs::{MAX_OUTPUTS, Bulletproofs},
    RctBase, RctPrunable, RctSignatures,
  },
  transaction::{Input, Output, Timelock, TransactionPrefix, Transaction},
  rpc::{RpcError, RpcConnection, Rpc},
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

async fn prepare_inputs<R: RngCore + CryptoRng, RPC: RpcConnection>(
  rng: &mut R,
  rpc: &Rpc<RPC>,
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
    rpc.get_height().await.map_err(TransactionError::RpcError)? - 1,
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

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) enum InternalPayment {
  Payment((MoneroAddress, u64)),
  Change(Change, u64),
}

/// The eventual output of a SignableTransaction.
///
/// If the SignableTransaction has a Change with a view key, this will also have the view key.
/// Accordingly, it must be treated securely.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Eventuality {
  protocol: Protocol,
  r_seed: Zeroizing<[u8; 32]>,
  inputs: Vec<EdwardsPoint>,
  payments: Vec<InternalPayment>,
  extra: Vec<u8>,
}

/// A signable transaction, either in a single-signer or multisig context.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SignableTransaction {
  protocol: Protocol,
  r_seed: Option<Zeroizing<[u8; 32]>>,
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

impl SignableTransaction {
  /// Create a signable transaction.
  ///
  /// `r_seed` refers to a seed used to derive the transaction's ephemeral keys (colloquially
  /// called Rs). If None is provided, one will be automatically generated.
  ///
  /// Up to 16 outputs may be present, including the change output. If the change address is
  /// specified, leftover funds will be sent to it.
  ///
  /// Each chunk of data must not exceed MAX_ARBITRARY_DATA_SIZE and will be embedded in TX extra.
  pub fn new(
    protocol: Protocol,
    r_seed: Option<Zeroizing<[u8; 32]>>,
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
    // Assume additional keys are needed in order to cause a worst-case estimation
    let extra = Extra::fee_weight(outputs, true, has_payment_id, data.as_ref());

    // https://github.com/monero-project/monero/pull/8733
    const MAX_EXTRA_SIZE: usize = 1060;
    if extra > MAX_EXTRA_SIZE {
      Err(TransactionError::TooMuchData)?;
    }

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

    Ok(SignableTransaction { protocol, r_seed, inputs, payments, data, fee })
  }

  pub fn fee(&self) -> u64 {
    self.fee
  }

  #[allow(clippy::type_complexity)]
  fn prepare_payments(
    seed: &Zeroizing<[u8; 32]>,
    inputs: &[EdwardsPoint],
    payments: &mut Vec<InternalPayment>,
    uniqueness: [u8; 32],
  ) -> (EdwardsPoint, Vec<Zeroizing<Scalar>>, Vec<SendOutput>, Option<[u8; 8]>) {
    let mut rng = {
      // Hash the inputs into the seed so we don't re-use Rs
      // Doesn't re-use uniqueness as that's based on key images, which requires interactivity
      // to generate. The output keys do not
      // This remains private so long as the seed is private
      let mut r_uniqueness = vec![];
      for input in inputs {
        r_uniqueness.extend(input.compress().to_bytes());
      }
      ChaCha20Rng::from_seed(hash(
        &[b"monero-serai_outputs".as_ref(), seed.as_ref(), &r_uniqueness].concat(),
      ))
    };

    // Shuffle the payments
    payments.shuffle(&mut rng);

    // Used for all non-subaddress outputs, or if there's only one subaddress output and a change
    let tx_key = Zeroizing::new(random_scalar(&mut rng));
    let mut tx_public_key = tx_key.deref() * &ED25519_BASEPOINT_TABLE;

    // If any of these outputs are to a subaddress, we need keys distinct to them
    // The only time this *does not* force having additional keys is when the only other output
    // is a change output we have the view key for, enabling rewriting rA to aR
    let mut has_change_view = false;
    let subaddresses = payments
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
    if (payments.len() == 2) && has_change_view {
      additional = false;
    }
    let modified_change_ecdh = subaddresses && (!additional);

    // If we're using the aR rewrite, update tx_public_key from rG to rB
    if modified_change_ecdh {
      for payment in &*payments {
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
    let mut additional_keys = vec![];
    let mut outputs = Vec::with_capacity(payments.len());
    let mut id = None;
    for (o, mut payment) in payments.drain(..).enumerate() {
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
          let dedicated = Zeroizing::new(random_scalar(&mut rng));
          let use_dedicated = additional && payment.0.is_subaddress();
          let r = if use_dedicated { &dedicated } else { &tx_key };

          let (mut output, payment_id) = SendOutput::new(r, uniqueness, (o, payment));
          if modified_change_ecdh {
            debug_assert_eq!(tx_public_key, output.R);
          }

          if use_dedicated {
            additional_keys.push(dedicated);
          } else {
            // If this used tx_key, randomize its R
            // This is so when extra is created, there's a distinct R for it to use
            output.R = dfg::EdwardsPoint::random(&mut rng).0;
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

    (tx_public_key, additional_keys, outputs, id)
  }

  #[allow(non_snake_case)]
  fn extra(
    tx_key: EdwardsPoint,
    additional: bool,
    Rs: Vec<EdwardsPoint>,
    id: Option<[u8; 8]>,
    data: &mut Vec<Vec<u8>>,
  ) -> Vec<u8> {
    #[allow(non_snake_case)]
    let Rs_len = Rs.len();
    let mut extra = Extra::new(tx_key, if additional { Rs } else { vec![] });

    if let Some(id) = id {
      let mut id_vec = Vec::with_capacity(1 + 8);
      PaymentId::Encrypted(id).write(&mut id_vec).unwrap();
      extra.push(ExtraField::Nonce(id_vec));
    }

    // Include data if present
    let extra_len = Extra::fee_weight(Rs_len, additional, id.is_some(), data.as_ref());
    for part in data.drain(..) {
      let mut arb = vec![ARBITRARY_DATA_MARKER];
      arb.extend(part);
      extra.push(ExtraField::Nonce(arb));
    }

    let mut serialized = Vec::with_capacity(extra_len);
    extra.write(&mut serialized).unwrap();
    debug_assert_eq!(extra_len, serialized.len());
    serialized
  }

  /// Returns the eventuality of this transaction.
  /// The eventuality is defined as the TX extra/outputs this transaction will create, if signed
  /// with the specified seed. This eventuality can be compared to on-chain transactions to see
  /// if the transaction has already been signed and published.
  pub fn eventuality(&self) -> Option<Eventuality> {
    let inputs = self.inputs.iter().map(|input| input.key()).collect::<Vec<_>>();
    let (tx_key, additional, outputs, id) = Self::prepare_payments(
      self.r_seed.as_ref()?,
      &inputs,
      &mut self.payments.clone(),
      // Lie about the uniqueness, used when determining output keys/commitments yet not the
      // ephemeral keys, which is want we want here
      // While we do still grab the outputs variable, it's so we can get its Rs
      [0; 32],
    );
    #[allow(non_snake_case)]
    let Rs = outputs.iter().map(|output| output.R).collect();
    drop(outputs);

    let additional = !additional.is_empty();
    let extra = Self::extra(tx_key, additional, Rs, id, &mut self.data.clone());

    Some(Eventuality {
      protocol: self.protocol,
      r_seed: self.r_seed.clone()?,
      inputs,
      payments: self.payments.clone(),
      extra,
    })
  }

  fn prepare_transaction<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    uniqueness: [u8; 32],
  ) -> (Transaction, Scalar) {
    // If no seed for the ephemeral keys was provided, make one
    let r_seed = self.r_seed.clone().unwrap_or_else(|| {
      let mut res = Zeroizing::new([0; 32]);
      rng.fill_bytes(res.as_mut());
      res
    });

    let (tx_key, additional, outputs, id) = Self::prepare_payments(
      &r_seed,
      &self.inputs.iter().map(|input| input.key()).collect::<Vec<_>>(),
      &mut self.payments,
      uniqueness,
    );
    // This function only cares if additional keys were necessary, not what they were
    let additional = !additional.is_empty();

    let commitments = outputs.iter().map(|output| output.commitment.clone()).collect::<Vec<_>>();
    let sum = commitments.iter().map(|commitment| commitment.mask).sum();

    // Safe due to the constructor checking MAX_OUTPUTS
    let bp = Bulletproofs::prove(rng, &commitments, self.protocol.bp_plus()).unwrap();

    // Create the TX extra
    let extra = Self::extra(
      tx_key,
      additional,
      outputs.iter().map(|output| output.R).collect(),
      id,
      &mut self.data,
    );

    let mut fee = self.inputs.iter().map(|input| input.commitment().amount).sum::<u64>();
    let mut tx_outputs = Vec::with_capacity(outputs.len());
    let mut ecdh_info = Vec::with_capacity(outputs.len());
    for output in &outputs {
      fee -= output.commitment.amount;
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
            fee,
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
  pub async fn sign<R: RngCore + CryptoRng, RPC: RpcConnection>(
    mut self,
    rng: &mut R,
    rpc: &Rpc<RPC>,
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

impl Eventuality {
  /// Enables building a HashMap of Extra -> Eventuality for efficiently checking if an on-chain
  /// transaction may match this eventuality.
  /// This extra is cryptographically bound to:
  /// 1) A specific set of inputs (via their output key)
  /// 2) A specific seed for the ephemeral keys
  pub fn extra(&self) -> &[u8] {
    &self.extra
  }

  pub fn matches(&self, tx: &Transaction) -> bool {
    if self.payments.len() != tx.prefix.outputs.len() {
      return false;
    }

    // Verify extra.
    // Even if all the outputs were correct, a malicious extra could still cause a recipient to
    // fail to receive their funds.
    // This is the cheapest check available to perform as it does not require TX-specific ECC ops.
    if self.extra != tx.prefix.extra {
      return false;
    }

    // Also ensure no timelock was set.
    if tx.prefix.timelock != Timelock::None {
      return false;
    }

    // Generate the outputs. This is TX-specific due to uniqueness.
    let (_, _, outputs, _) = SignableTransaction::prepare_payments(
      &self.r_seed,
      &self.inputs,
      &mut self.payments.clone(),
      uniqueness(&tx.prefix.inputs),
    );

    for (o, (expected, actual)) in outputs.iter().zip(tx.prefix.outputs.iter()).enumerate() {
      // Verify the output, commitment, and encrypted amount.
      if (&Output {
        amount: 0,
        key: expected.dest.compress(),
        view_tag: Some(expected.view_tag).filter(|_| matches!(self.protocol, Protocol::v16)),
      } != actual) ||
        (Some(&expected.commitment.calculate()) != tx.rct_signatures.base.commitments.get(o)) ||
        (Some(&expected.amount) != tx.rct_signatures.base.ecdh_info.get(o))
      {
        return false;
      }
    }

    true
  }

  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    self.protocol.write(w)?;
    write_raw_vec(write_byte, self.r_seed.as_ref(), w)?;
    write_vec(write_point, &self.inputs, w)?;

    fn write_payment<W: io::Write>(payment: &InternalPayment, w: &mut W) -> io::Result<()> {
      match payment {
        InternalPayment::Payment(payment) => {
          w.write_all(&[0])?;
          write_vec(write_byte, payment.0.to_string().as_bytes(), w)?;
          w.write_all(&payment.1.to_le_bytes())
        }
        InternalPayment::Change(change, amount) => {
          w.write_all(&[1])?;
          write_vec(write_byte, change.address.to_string().as_bytes(), w)?;
          if let Some(view) = change.view.as_ref() {
            w.write_all(&[1])?;
            write_scalar(view, w)?;
          } else {
            w.write_all(&[0])?;
          }
          w.write_all(&amount.to_le_bytes())
        }
      }
    }
    write_vec(write_payment, &self.payments, w)?;

    write_vec(write_byte, &self.extra, w)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    self.write(&mut buf).unwrap();
    buf
  }

  pub fn read<R: io::Read>(r: &mut R) -> io::Result<Eventuality> {
    fn read_address<R: io::Read>(r: &mut R) -> io::Result<MoneroAddress> {
      String::from_utf8(read_vec(read_byte, r)?)
        .ok()
        .and_then(|str| MoneroAddress::from_str_raw(&str).ok())
        .ok_or(io::Error::new(io::ErrorKind::Other, "invalid address"))
    }

    fn read_payment<R: io::Read>(r: &mut R) -> io::Result<InternalPayment> {
      Ok(match read_byte(r)? {
        0 => InternalPayment::Payment((read_address(r)?, read_u64(r)?)),
        1 => InternalPayment::Change(
          Change {
            address: read_address(r)?,
            view: match read_byte(r)? {
              0 => None,
              1 => Some(Zeroizing::new(read_scalar(r)?)),
              _ => Err(io::Error::new(io::ErrorKind::Other, "invalid change payment"))?,
            },
          },
          read_u64(r)?,
        ),
        _ => Err(io::Error::new(io::ErrorKind::Other, "invalid payment"))?,
      })
    }

    Ok(Eventuality {
      protocol: Protocol::read(r)?,
      r_seed: Zeroizing::new(read_bytes::<_, 32>(r)?),
      inputs: read_vec(read_point, r)?,
      payments: read_vec(read_payment, r)?,
      extra: read_vec(read_byte, r)?,
    })
  }
}

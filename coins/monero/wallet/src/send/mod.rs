use core::{ops::Deref, fmt};
use std_shims::io;

use zeroize::{Zeroize, Zeroizing};

use rand_core::{RngCore, CryptoRng};
use rand::seq::SliceRandom;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar, EdwardsPoint};
#[cfg(feature = "multisig")]
use frost::FrostError;

use crate::{
  io::*,
  generators::{MAX_COMMITMENTS, hash_to_point},
  primitives::Decoys,
  ringct::{
    clsag::{ClsagError, ClsagContext, Clsag},
    RctType, RctPrunable, RctProofs,
  },
  transaction::Transaction,
  extra::MAX_ARBITRARY_DATA_SIZE,
  address::{Network, AddressSpec, MoneroAddress},
  rpc::FeeRate,
  ViewPair,
  scan::SpendableOutput,
};

mod tx_keys;
mod tx;
mod eventuality;
pub use eventuality::Eventuality;

#[cfg(feature = "multisig")]
mod multisig;

pub(crate) fn key_image_sort(x: &EdwardsPoint, y: &EdwardsPoint) -> core::cmp::Ordering {
  x.compress().to_bytes().cmp(&y.compress().to_bytes()).reverse()
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
enum ChangeEnum {
  None,
  AddressOnly(MoneroAddress),
  AddressWithView(MoneroAddress, Zeroizing<Scalar>),
}

impl fmt::Debug for ChangeEnum {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ChangeEnum::None => f.debug_struct("ChangeEnum::None").finish_non_exhaustive(),
      ChangeEnum::AddressOnly(addr) => {
        f.debug_struct("ChangeEnum::AddressOnly").field("addr", &addr).finish()
      }
      ChangeEnum::AddressWithView(addr, _) => {
        f.debug_struct("ChangeEnum::AddressWithView").field("addr", &addr).finish_non_exhaustive()
      }
    }
  }
}

/// Specification for a change output.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Change(ChangeEnum);

impl Change {
  /// Create a change output specification.
  ///
  /// This take the view key as Monero assumes it has the view key for change outputs. It optimizes
  /// its wallet protocol accordingly.
  // TODO: Accept AddressSpec, not `guaranteed: bool`
  pub fn new(view: &ViewPair, guaranteed: bool) -> Change {
    Change(ChangeEnum::AddressWithView(
      view.address(
        // Which network doesn't matter as the derivations will all be the same
        Network::Mainnet,
        if !guaranteed {
          AddressSpec::Standard
        } else {
          AddressSpec::Featured { subaddress: None, payment_id: None, guaranteed: true }
        },
      ),
      view.view.clone(),
    ))
  }

  /// Create a fingerprintable change output specification.
  ///
  /// You MUST assume this will harm your privacy. Only use this if you know what you're doing.
  ///
  /// If the change address is Some, this will be unable to optimize the transaction as the
  /// Monero wallet protocol expects it can (due to presumably having the view key for the change
  /// output). If a transaction should be optimized, and isn'tm it will be fingerprintable.
  ///
  /// If the change address is None, there are two fingerprints:
  ///
  /// 1) The change in the TX is shunted to the fee (making it fingerprintable).
  ///
  /// 2) If there are two outputs in the TX, Monero would create a payment ID for the non-change
  ///    output so an observer can't tell apart TXs with a payment ID from TXs without a payment
  ///    ID. monero-wallet will simply not create a payment ID in this case, revealing it's a
  ///    monero-wallet TX without change.
  pub fn fingerprintable(address: Option<MoneroAddress>) -> Change {
    if let Some(address) = address {
      Change(ChangeEnum::AddressOnly(address))
    } else {
      Change(ChangeEnum::None)
    }
  }
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
enum InternalPayment {
  Payment(MoneroAddress, u64),
  Change(MoneroAddress, Option<Zeroizing<Scalar>>),
}

impl InternalPayment {
  fn address(&self) -> &MoneroAddress {
    match self {
      InternalPayment::Payment(addr, _) | InternalPayment::Change(addr, _) => addr,
    }
  }
}

impl fmt::Debug for InternalPayment {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      InternalPayment::Payment(addr, amount) => f
        .debug_struct("InternalPayment::Payment")
        .field("addr", &addr)
        .field("amount", &amount)
        .finish(),
      InternalPayment::Change(addr, _) => {
        f.debug_struct("InternalPayment::Change").field("addr", &addr).finish_non_exhaustive()
      }
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SendError {
  #[cfg_attr(feature = "std", error("this library doesn't yet support that RctType"))]
  UnsupportedRctType,
  #[cfg_attr(feature = "std", error("no inputs"))]
  NoInputs,
  #[cfg_attr(feature = "std", error("invalid number of decoys"))]
  InvalidDecoyQuantity,
  #[cfg_attr(feature = "std", error("no outputs"))]
  NoOutputs,
  #[cfg_attr(feature = "std", error("too many outputs"))]
  TooManyOutputs,
  #[cfg_attr(feature = "std", error("only one output and no change address"))]
  NoChange,
  #[cfg_attr(feature = "std", error("multiple addresses with payment IDs"))]
  MultiplePaymentIds,
  #[cfg_attr(feature = "std", error("too much data"))]
  TooMuchData,
  #[cfg_attr(feature = "std", error("too many inputs/too much arbitrary data"))]
  TooLargeTransaction,
  #[cfg_attr(
    feature = "std",
    error("not enough funds (inputs {inputs}, outputs {outputs}, fee {fee:?})")
  )]
  NotEnoughFunds { inputs: u64, outputs: u64, fee: Option<u64> },
  #[cfg_attr(feature = "std", error("invalid amount of key images specified"))]
  InvalidAmountOfKeyImages,
  #[cfg_attr(feature = "std", error("wrong spend private key"))]
  WrongPrivateKey,
  #[cfg_attr(
    feature = "std",
    error("this SignableTransaction was created by deserializing a malicious serialization")
  )]
  MaliciousSerialization,
  #[cfg_attr(feature = "std", error("clsag error ({0})"))]
  ClsagError(ClsagError),
  #[cfg(feature = "multisig")]
  #[cfg_attr(feature = "std", error("frost error {0}"))]
  FrostError(FrostError),
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct SignableTransaction {
  rct_type: RctType,
  sender_view_key: Zeroizing<Scalar>,
  inputs: Vec<(SpendableOutput, Decoys)>,
  payments: Vec<InternalPayment>,
  data: Vec<Vec<u8>>,
  fee_rate: FeeRate,
}

struct SignableTransactionWithKeyImages {
  intent: SignableTransaction,
  key_images: Vec<EdwardsPoint>,
}

impl SignableTransaction {
  fn validate(&self) -> Result<(), SendError> {
    match self.rct_type {
      RctType::ClsagBulletproof | RctType::ClsagBulletproofPlus => {}
      _ => Err(SendError::UnsupportedRctType)?,
    }

    if self.inputs.is_empty() {
      Err(SendError::NoInputs)?;
    }
    for (_, decoys) in &self.inputs {
      if decoys.len() !=
        match self.rct_type {
          RctType::ClsagBulletproof => 11,
          RctType::ClsagBulletproofPlus => 16,
          _ => panic!("unsupported RctType"),
        }
      {
        Err(SendError::InvalidDecoyQuantity)?;
      }
    }

    // Check we have at least one non-change output
    if !self.payments.iter().any(|payment| matches!(payment, InternalPayment::Payment(_, _))) {
      Err(SendError::NoOutputs)?;
    }
    // If we don't have at least two outputs, as required by Monero, error
    if self.payments.len() < 2 {
      Err(SendError::NoChange)?;
    }
    // Check we don't have multiple Change outputs due to decoding a malicious serialization
    {
      let mut change_count = 0;
      for payment in &self.payments {
        change_count += usize::from(u8::from(matches!(payment, InternalPayment::Change(_, _))));
      }
      if change_count > 1 {
        Err(SendError::MaliciousSerialization)?;
      }
    }

    // Make sure there's at most one payment ID
    {
      let mut payment_ids = 0;
      for payment in &self.payments {
        payment_ids += usize::from(u8::from(payment.address().payment_id().is_some()));
      }
      if payment_ids > 1 {
        Err(SendError::MultiplePaymentIds)?;
      }
    }

    if self.payments.len() > MAX_COMMITMENTS {
      Err(SendError::TooManyOutputs)?;
    }

    // Check the length of each arbitrary data
    for part in &self.data {
      if part.len() > MAX_ARBITRARY_DATA_SIZE {
        Err(SendError::TooMuchData)?;
      }
    }

    // Check the length of TX extra
    // https://github.com/monero-project/monero/pull/8733
    const MAX_EXTRA_SIZE: usize = 1060;
    if self.extra().len() > MAX_EXTRA_SIZE {
      Err(SendError::TooMuchData)?;
    }

    // Make sure we have enough funds
    let in_amount = self.inputs.iter().map(|(input, _)| input.commitment().amount).sum::<u64>();
    let payments_amount = self
      .payments
      .iter()
      .filter_map(|payment| match payment {
        InternalPayment::Payment(_, amount) => Some(amount),
        InternalPayment::Change(_, _) => None,
      })
      .sum::<u64>();
    // Necessary so weight_and_fee doesn't underflow
    if in_amount < payments_amount {
      Err(SendError::NotEnoughFunds { inputs: in_amount, outputs: payments_amount, fee: None })?;
    }
    let (weight, fee) = self.weight_and_fee();
    if in_amount < (payments_amount + fee) {
      Err(SendError::NotEnoughFunds {
        inputs: in_amount,
        outputs: payments_amount,
        fee: Some(fee),
      })?;
    }

    // The actual limit is half the block size, and for the minimum block size of 300k, that'd be
    // 150k
    // wallet2 will only create transactions up to 100k bytes however
    const MAX_TX_SIZE: usize = 100_000;
    if weight >= MAX_TX_SIZE {
      Err(SendError::TooLargeTransaction)?;
    }

    Ok(())
  }

  pub fn new(
    rct_type: RctType,
    sender_view_key: Zeroizing<Scalar>,
    inputs: Vec<(SpendableOutput, Decoys)>,
    payments: Vec<(MoneroAddress, u64)>,
    change: Change,
    data: Vec<Vec<u8>>,
    fee_rate: FeeRate,
  ) -> Result<SignableTransaction, SendError> {
    // Re-format the payments and change into a consolidated payments list
    let mut payments = payments
      .into_iter()
      .map(|(addr, amount)| InternalPayment::Payment(addr, amount))
      .collect::<Vec<_>>();
    match change.0 {
      ChangeEnum::None => {}
      ChangeEnum::AddressOnly(addr) => payments.push(InternalPayment::Change(addr, None)),
      ChangeEnum::AddressWithView(addr, view) => {
        payments.push(InternalPayment::Change(addr, Some(view)))
      }
    }

    let res = SignableTransaction { rct_type, sender_view_key, inputs, payments, data, fee_rate };
    res.validate()?;
    Ok(res)
  }

  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    fn write_input<W: io::Write>(input: &(SpendableOutput, Decoys), w: &mut W) -> io::Result<()> {
      input.0.write(w)?;
      input.1.write(w)
    }

    fn write_payment<W: io::Write>(payment: &InternalPayment, w: &mut W) -> io::Result<()> {
      match payment {
        InternalPayment::Payment(addr, amount) => {
          w.write_all(&[0])?;
          write_vec(write_byte, addr.to_string().as_bytes(), w)?;
          w.write_all(&amount.to_le_bytes())
        }
        InternalPayment::Change(addr, change_view) => {
          w.write_all(&[1])?;
          write_vec(write_byte, addr.to_string().as_bytes(), w)?;
          if let Some(view) = change_view.as_ref() {
            w.write_all(&[1])?;
            write_scalar(view, w)
          } else {
            w.write_all(&[0])
          }
        }
      }
    }

    write_byte(&u8::from(self.rct_type), w)?;
    write_scalar(&self.sender_view_key, w)?;
    write_vec(write_input, &self.inputs, w)?;
    write_vec(write_payment, &self.payments, w)?;
    write_vec(|data, w| write_vec(write_byte, data, w), &self.data, w)?;
    self.fee_rate.write(w)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    self.write(&mut buf).unwrap();
    buf
  }

  pub fn read<R: io::Read>(r: &mut R) -> io::Result<SignableTransaction> {
    fn read_input(r: &mut impl io::Read) -> io::Result<(SpendableOutput, Decoys)> {
      Ok((SpendableOutput::read(r)?, Decoys::read(r)?))
    }

    fn read_address<R: io::Read>(r: &mut R) -> io::Result<MoneroAddress> {
      String::from_utf8(read_vec(read_byte, r)?)
        .ok()
        .and_then(|str| MoneroAddress::from_str_raw(&str).ok())
        .ok_or_else(|| io::Error::other("invalid address"))
    }

    fn read_payment<R: io::Read>(r: &mut R) -> io::Result<InternalPayment> {
      Ok(match read_byte(r)? {
        0 => InternalPayment::Payment(read_address(r)?, read_u64(r)?),
        1 => InternalPayment::Change(
          read_address(r)?,
          match read_byte(r)? {
            0 => None,
            1 => Some(Zeroizing::new(read_scalar(r)?)),
            _ => Err(io::Error::other("invalid change view"))?,
          },
        ),
        _ => Err(io::Error::other("invalid payment"))?,
      })
    }

    let res = SignableTransaction {
      rct_type: RctType::try_from(read_byte(r)?)
        .map_err(|()| io::Error::other("unsupported/invalid RctType"))?,
      sender_view_key: Zeroizing::new(read_scalar(r)?),
      inputs: read_vec(read_input, r)?,
      payments: read_vec(read_payment, r)?,
      data: read_vec(|r| read_vec(read_byte, r), r)?,
      fee_rate: FeeRate::read(r)?,
    };
    match res.validate() {
      Ok(()) => {}
      Err(e) => Err(io::Error::other(e))?,
    }
    Ok(res)
  }

  fn with_key_images(mut self, key_images: Vec<EdwardsPoint>) -> SignableTransactionWithKeyImages {
    debug_assert_eq!(self.inputs.len(), key_images.len());

    // Sort the inputs by their key images
    let mut sorted_inputs = self.inputs.into_iter().zip(key_images).collect::<Vec<_>>();
    sorted_inputs
      .sort_by(|(_, key_image_a), (_, key_image_b)| key_image_sort(key_image_a, key_image_b));

    self.inputs = Vec::with_capacity(sorted_inputs.len());
    let mut key_images = Vec::with_capacity(sorted_inputs.len());
    for (input, key_image) in sorted_inputs {
      self.inputs.push(input);
      key_images.push(key_image);
    }

    // Shuffle the payments
    {
      let mut rng = self.seeded_rng(b"shuffle_payments");
      self.payments.shuffle(&mut rng);
    }

    SignableTransactionWithKeyImages { intent: self, key_images }
  }

  pub fn sign(
    self,
    rng: &mut (impl RngCore + CryptoRng),
    sender_spend_key: &Zeroizing<Scalar>,
  ) -> Result<Transaction, SendError> {
    // Calculate the key images
    let mut key_images = vec![];
    for (input, _) in &self.inputs {
      let input_key = Zeroizing::new(sender_spend_key.deref() + input.key_offset());
      if (input_key.deref() * ED25519_BASEPOINT_TABLE) != input.key() {
        Err(SendError::WrongPrivateKey)?;
      }
      let key_image = input_key.deref() * hash_to_point(input.key().compress().to_bytes());
      key_images.push(key_image);
    }

    // Convert to a SignableTransactionWithKeyImages
    let tx = self.with_key_images(key_images);

    // Prepare the CLSAG signatures
    let mut clsag_signs = Vec::with_capacity(tx.intent.inputs.len());
    for (input, decoys) in &tx.intent.inputs {
      // Re-derive the input key as this will be in a different order
      let input_key = Zeroizing::new(sender_spend_key.deref() + input.key_offset());
      clsag_signs.push((
        input_key,
        ClsagContext::new(decoys.clone(), input.commitment().clone())
          .map_err(SendError::ClsagError)?,
      ));
    }

    // Get the output commitments' mask sum
    let mask_sum = tx.intent.sum_output_masks(&tx.key_images);

    // Get the actual TX, just needing the CLSAGs
    let mut tx = tx.transaction_without_signatures();

    // Sign the CLSAGs
    let clsags_and_pseudo_outs =
      Clsag::sign(rng, clsag_signs, mask_sum, tx.signature_hash().unwrap())
        .map_err(SendError::ClsagError)?;

    // Fill in the CLSAGs/pseudo-outs
    let inputs_len = tx.prefix().inputs.len();
    let Transaction::V2 {
      proofs:
        Some(RctProofs {
          prunable: RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. },
          ..
        }),
      ..
    } = tx
    else {
      panic!("not signing clsag?")
    };
    *clsags = Vec::with_capacity(inputs_len);
    *pseudo_outs = Vec::with_capacity(inputs_len);
    for (clsag, pseudo_out) in clsags_and_pseudo_outs {
      clsags.push(clsag);
      pseudo_outs.push(pseudo_out);
    }

    // Return the signed TX
    Ok(tx)
  }
}

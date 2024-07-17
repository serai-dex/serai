use core::{ops::Deref, fmt};
use std_shims::{
  io, vec,
  vec::Vec,
  string::{String, ToString},
};

use zeroize::{Zeroize, Zeroizing};

use rand_core::{RngCore, CryptoRng};
use rand::seq::SliceRandom;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar, EdwardsPoint};
#[cfg(feature = "multisig")]
use frost::FrostError;

use crate::{
  io::*,
  generators::{MAX_COMMITMENTS, hash_to_point},
  ringct::{
    clsag::{ClsagError, ClsagContext, Clsag},
    RctType, RctPrunable, RctProofs,
  },
  transaction::Transaction,
  address::{Network, SubaddressIndex, MoneroAddress},
  extra::MAX_ARBITRARY_DATA_SIZE,
  rpc::FeeRate,
  ViewPair, GuaranteedViewPair, OutputWithDecoys,
};

mod tx_keys;
mod tx;
mod eventuality;
pub use eventuality::Eventuality;

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use multisig::{TransactionMachine, TransactionSignMachine, TransactionSignatureMachine};

pub(crate) fn key_image_sort(x: &EdwardsPoint, y: &EdwardsPoint) -> core::cmp::Ordering {
  x.compress().to_bytes().cmp(&y.compress().to_bytes()).reverse()
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
enum ChangeEnum {
  AddressOnly(MoneroAddress),
  Standard { view_pair: ViewPair, subaddress: Option<SubaddressIndex> },
  Guaranteed { view_pair: GuaranteedViewPair, subaddress: Option<SubaddressIndex> },
}

impl fmt::Debug for ChangeEnum {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ChangeEnum::AddressOnly(addr) => {
        f.debug_struct("ChangeEnum::AddressOnly").field("addr", &addr).finish()
      }
      ChangeEnum::Standard { subaddress, .. } => f
        .debug_struct("ChangeEnum::Standard")
        .field("subaddress", &subaddress)
        .finish_non_exhaustive(),
      ChangeEnum::Guaranteed { subaddress, .. } => f
        .debug_struct("ChangeEnum::Guaranteed")
        .field("subaddress", &subaddress)
        .finish_non_exhaustive(),
    }
  }
}

/// Specification for a change output.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Change(Option<ChangeEnum>);

impl Change {
  /// Create a change output specification.
  ///
  /// This take the view key as Monero assumes it has the view key for change outputs. It optimizes
  /// its wallet protocol accordingly.
  pub fn new(view_pair: ViewPair, subaddress: Option<SubaddressIndex>) -> Change {
    Change(Some(ChangeEnum::Standard { view_pair, subaddress }))
  }

  /// Create a change output specification for a guaranteed view pair.
  ///
  /// This take the view key as Monero assumes it has the view key for change outputs. It optimizes
  /// its wallet protocol accordingly.
  pub fn guaranteed(view_pair: GuaranteedViewPair, subaddress: Option<SubaddressIndex>) -> Change {
    Change(Some(ChangeEnum::Guaranteed { view_pair, subaddress }))
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
      Change(Some(ChangeEnum::AddressOnly(address)))
    } else {
      Change(None)
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
enum InternalPayment {
  Payment(MoneroAddress, u64),
  Change(ChangeEnum),
}

impl InternalPayment {
  fn address(&self) -> MoneroAddress {
    match self {
      InternalPayment::Payment(addr, _) => *addr,
      InternalPayment::Change(change) => match change {
        ChangeEnum::AddressOnly(addr) => *addr,
        // Network::Mainnet as the network won't effect the derivations
        ChangeEnum::Standard { view_pair, subaddress } => match subaddress {
          Some(subaddress) => view_pair.subaddress(Network::Mainnet, *subaddress),
          None => view_pair.legacy_address(Network::Mainnet),
        },
        ChangeEnum::Guaranteed { view_pair, subaddress } => {
          view_pair.address(Network::Mainnet, *subaddress, None)
        }
      },
    }
  }
}

/// An error while sending Monero.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SendError {
  /// The RingCT type to produce proofs for this transaction with weren't supported.
  #[cfg_attr(feature = "std", error("this library doesn't yet support that RctType"))]
  UnsupportedRctType,
  /// The transaction had no inputs specified.
  #[cfg_attr(feature = "std", error("no inputs"))]
  NoInputs,
  /// The decoy quantity was invalid for the specified RingCT type.
  #[cfg_attr(feature = "std", error("invalid number of decoys"))]
  InvalidDecoyQuantity,
  /// The transaction had no outputs specified.
  #[cfg_attr(feature = "std", error("no outputs"))]
  NoOutputs,
  /// The transaction had too many outputs specified.
  #[cfg_attr(feature = "std", error("too many outputs"))]
  TooManyOutputs,
  /// The transaction did not have a change output, and did not have two outputs.
  ///
  /// Monero requires all transactions have at least two outputs, assuming one payment and one
  /// change (or at least one dummy and one change). Accordingly, specifying no change and only
  /// one payment prevents creating a valid transaction
  #[cfg_attr(feature = "std", error("only one output and no change address"))]
  NoChange,
  /// Multiple addresses had payment IDs specified.
  ///
  /// Only one payment ID is allowed per transaction.
  #[cfg_attr(feature = "std", error("multiple addresses with payment IDs"))]
  MultiplePaymentIds,
  /// Too much arbitrary data was specified.
  #[cfg_attr(feature = "std", error("too much data"))]
  TooMuchArbitraryData,
  /// The created transaction was too large.
  #[cfg_attr(feature = "std", error("too large of a transaction"))]
  TooLargeTransaction,
  /// This transaction could not pay for itself.
  #[cfg_attr(
    feature = "std",
    error(
      "not enough funds (inputs {inputs}, outputs {outputs}, necessary_fee {necessary_fee:?})"
    )
  )]
  NotEnoughFunds {
    /// The amount of funds the inputs contributed.
    inputs: u64,
    /// The amount of funds the outputs required.
    outputs: u64,
    /// The fee necessary to be paid on top.
    ///
    /// If this is None, it is because the fee was not calculated as the outputs alone caused this
    /// error.
    necessary_fee: Option<u64>,
  },
  /// This transaction is being signed with the wrong private key.
  #[cfg_attr(feature = "std", error("wrong spend private key"))]
  WrongPrivateKey,
  /// This transaction was read from a bytestream which was malicious.
  #[cfg_attr(
    feature = "std",
    error("this SignableTransaction was created by deserializing a malicious serialization")
  )]
  MaliciousSerialization,
  /// There was an error when working with the CLSAGs.
  #[cfg_attr(feature = "std", error("clsag error ({0})"))]
  ClsagError(ClsagError),
  /// There was an error when working with FROST.
  #[cfg(feature = "multisig")]
  #[cfg_attr(feature = "std", error("frost error {0}"))]
  FrostError(FrostError),
}

/// A signable transaction.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct SignableTransaction {
  rct_type: RctType,
  outgoing_view_key: Zeroizing<[u8; 32]>,
  inputs: Vec<OutputWithDecoys>,
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
    for input in &self.inputs {
      if input.decoys().len() !=
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
        change_count += usize::from(u8::from(matches!(payment, InternalPayment::Change(_))));
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
        Err(SendError::TooMuchArbitraryData)?;
      }
    }

    // Check the length of TX extra
    // https://github.com/monero-project/monero/pull/8733
    const MAX_EXTRA_SIZE: usize = 1060;
    if self.extra().len() > MAX_EXTRA_SIZE {
      Err(SendError::TooMuchArbitraryData)?;
    }

    // Make sure we have enough funds
    let in_amount = self.inputs.iter().map(|input| input.commitment().amount).sum::<u64>();
    let payments_amount = self
      .payments
      .iter()
      .filter_map(|payment| match payment {
        InternalPayment::Payment(_, amount) => Some(amount),
        InternalPayment::Change(_) => None,
      })
      .sum::<u64>();
    let (weight, necessary_fee) = self.weight_and_necessary_fee();
    if in_amount < (payments_amount + necessary_fee) {
      Err(SendError::NotEnoughFunds {
        inputs: in_amount,
        outputs: payments_amount,
        necessary_fee: Some(necessary_fee),
      })?;
    }

    // The limit is half the no-penalty block size
    // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
    //   /src/wallet/wallet2.cpp#L110766-L11085
    // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
    //   /src/cryptonote_config.h#L61
    // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
    //   /src/cryptonote_config.h#L64
    const MAX_TX_SIZE: usize = (300_000 / 2) - 600;
    if weight >= MAX_TX_SIZE {
      Err(SendError::TooLargeTransaction)?;
    }

    Ok(())
  }

  /// Create a new SignableTransaction.
  ///
  /// `outgoing_view_key` is used to seed the RNGs for this transaction. Anyone with knowledge of
  /// the outgoing view key will be able to identify a transaction produced with this methodology,
  /// and the data within it. Accordingly, it must be treated as a private key.
  ///
  /// `data` represents arbitrary data which will be embedded into the transaction's `extra` field.
  /// The embedding occurs using an `ExtraField::Nonce` with a custom marker byte (as to not
  /// conflict with a payment ID).
  pub fn new(
    rct_type: RctType,
    outgoing_view_key: Zeroizing<[u8; 32]>,
    inputs: Vec<OutputWithDecoys>,
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

    if let Some(change) = change.0 {
      payments.push(InternalPayment::Change(change));
    }

    let mut res =
      SignableTransaction { rct_type, outgoing_view_key, inputs, payments, data, fee_rate };
    res.validate()?;

    // Shuffle the payments
    {
      let mut rng = res.seeded_rng(b"shuffle_payments");
      res.payments.shuffle(&mut rng);
    }

    Ok(res)
  }

  /// The fee rate this transaction uses.
  pub fn fee_rate(&self) -> FeeRate {
    self.fee_rate
  }

  /// The fee this transaction requires.
  ///
  /// This is distinct from the fee this transaction will use. If no change output is specified,
  /// all unspent coins will be shunted to the fee.
  pub fn necessary_fee(&self) -> u64 {
    self.weight_and_necessary_fee().1
  }

  /// Write a SignableTransaction.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    fn write_payment<W: io::Write>(payment: &InternalPayment, w: &mut W) -> io::Result<()> {
      match payment {
        InternalPayment::Payment(addr, amount) => {
          w.write_all(&[0])?;
          write_vec(write_byte, addr.to_string().as_bytes(), w)?;
          w.write_all(&amount.to_le_bytes())
        }
        InternalPayment::Change(change) => match change {
          ChangeEnum::AddressOnly(addr) => {
            w.write_all(&[1])?;
            write_vec(write_byte, addr.to_string().as_bytes(), w)
          }
          ChangeEnum::Standard { view_pair, subaddress } => {
            w.write_all(&[2])?;
            write_point(&view_pair.spend(), w)?;
            write_scalar(&view_pair.view, w)?;
            if let Some(subaddress) = subaddress {
              w.write_all(&subaddress.account().to_le_bytes())?;
              w.write_all(&subaddress.address().to_le_bytes())
            } else {
              w.write_all(&0u32.to_le_bytes())?;
              w.write_all(&0u32.to_le_bytes())
            }
          }
          ChangeEnum::Guaranteed { view_pair, subaddress } => {
            w.write_all(&[3])?;
            write_point(&view_pair.spend(), w)?;
            write_scalar(&view_pair.0.view, w)?;
            if let Some(subaddress) = subaddress {
              w.write_all(&subaddress.account().to_le_bytes())?;
              w.write_all(&subaddress.address().to_le_bytes())
            } else {
              w.write_all(&0u32.to_le_bytes())?;
              w.write_all(&0u32.to_le_bytes())
            }
          }
        },
      }
    }

    write_byte(&u8::from(self.rct_type), w)?;
    w.write_all(self.outgoing_view_key.as_slice())?;
    write_vec(OutputWithDecoys::write, &self.inputs, w)?;
    write_vec(write_payment, &self.payments, w)?;
    write_vec(|data, w| write_vec(write_byte, data, w), &self.data, w)?;
    self.fee_rate.write(w)
  }

  /// Serialize the SignableTransaction to a `Vec<u8>`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    self.write(&mut buf).unwrap();
    buf
  }

  /// Read a `SignableTransaction`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn read<R: io::Read>(r: &mut R) -> io::Result<SignableTransaction> {
    fn read_address<R: io::Read>(r: &mut R) -> io::Result<MoneroAddress> {
      String::from_utf8(read_vec(read_byte, r)?)
        .ok()
        .and_then(|str| MoneroAddress::from_str_with_unchecked_network(&str).ok())
        .ok_or_else(|| io::Error::other("invalid address"))
    }

    fn read_payment<R: io::Read>(r: &mut R) -> io::Result<InternalPayment> {
      Ok(match read_byte(r)? {
        0 => InternalPayment::Payment(read_address(r)?, read_u64(r)?),
        1 => InternalPayment::Change(ChangeEnum::AddressOnly(read_address(r)?)),
        2 => InternalPayment::Change(ChangeEnum::Standard {
          view_pair: ViewPair::new(read_point(r)?, Zeroizing::new(read_scalar(r)?))
            .map_err(io::Error::other)?,
          subaddress: SubaddressIndex::new(read_u32(r)?, read_u32(r)?),
        }),
        3 => InternalPayment::Change(ChangeEnum::Guaranteed {
          view_pair: GuaranteedViewPair::new(read_point(r)?, Zeroizing::new(read_scalar(r)?))
            .map_err(io::Error::other)?,
          subaddress: SubaddressIndex::new(read_u32(r)?, read_u32(r)?),
        }),
        _ => Err(io::Error::other("invalid payment"))?,
      })
    }

    let res = SignableTransaction {
      rct_type: RctType::try_from(read_byte(r)?)
        .map_err(|()| io::Error::other("unsupported/invalid RctType"))?,
      outgoing_view_key: Zeroizing::new(read_bytes(r)?),
      inputs: read_vec(OutputWithDecoys::read, r)?,
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

    SignableTransactionWithKeyImages { intent: self, key_images }
  }

  /// Sign this transaction.
  pub fn sign(
    self,
    rng: &mut (impl RngCore + CryptoRng),
    sender_spend_key: &Zeroizing<Scalar>,
  ) -> Result<Transaction, SendError> {
    // Calculate the key images
    let mut key_images = vec![];
    for input in &self.inputs {
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
    for input in &tx.intent.inputs {
      // Re-derive the input key as this will be in a different order
      let input_key = Zeroizing::new(sender_spend_key.deref() + input.key_offset());
      clsag_signs.push((
        input_key,
        ClsagContext::new(input.decoys().clone(), input.commitment().clone())
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

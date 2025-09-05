use core::num::NonZero;
use alloc::vec::Vec;

use borsh::{io, BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};
use serai_primitives::{BlockHash, address::SeraiAddress, balance::Amount, crypto::Signature};
use crate::Call;

/// The maximum amount of calls allowed in a transaction.
pub const MAX_CALLS: u32 = 8;

/// An error regarding `SignedCalls`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SignedCallsError {
  /// No calls were included.
  NoCalls,
  /// Too many calls were included.
  TooManyCalls,
  /// An unsigned call was included.
  IncludedUnsignedCall,
}

/// A `Vec` of signed calls.
// We don't implement BorshDeserialize due to to maintained invariants on this struct.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize)]
pub struct SignedCalls(
  #[borsh(serialize_with = "serai_primitives::sp_borsh::borsh_serialize_bounded_vec")]
  BoundedVec<Call, ConstU32<{ MAX_CALLS }>>,
);
impl TryFrom<Vec<Call>> for SignedCalls {
  type Error = SignedCallsError;
  fn try_from(calls: Vec<Call>) -> Result<Self, Self::Error> {
    if calls.is_empty() {
      Err(SignedCallsError::NoCalls)?;
    }
    for call in &calls {
      if !call.is_signed() {
        Err(SignedCallsError::IncludedUnsignedCall)?;
      }
    }
    calls.try_into().map_err(|_| SignedCallsError::TooManyCalls).map(SignedCalls)
  }
}

/// An error regarding `UnsignedCall`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UnsignedCallError {
  /// A signed call was specified.
  SignedCall,
}

/// An unsigned call.
// We don't implement BorshDeserialize due to to maintained invariants on this struct.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize)]
pub struct UnsignedCall(Call);
impl TryFrom<Call> for UnsignedCall {
  type Error = UnsignedCallError;
  fn try_from(call: Call) -> Result<Self, Self::Error> {
    if call.is_signed() {
      Err(UnsignedCallError::SignedCall)?;
    }
    Ok(UnsignedCall(call))
  }
}

/// Part of the context used to sign with, from the protocol.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ImplicitContext {
  /// The genesis hash of the blockchain.
  pub genesis: BlockHash,
  /// The ID of the current protocol.
  pub protocol_id: [u8; 32],
}

/// Part of the context used to sign with, specified within the transaction itself.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ExplicitContext {
  /// The historic block this transaction builds upon.
  ///
  /// This transaction can not be included in a blockchain which does not include this block.
  pub historic_block: BlockHash,

  /// The UNIX time this transaction must be included by (and expires after).
  ///
  /// This transaction can not be included in a block whose time is equal or greater to this value.
  pub include_by: Option<NonZero<u64>>,

  /// The signer.
  pub signer: SeraiAddress,

  /// The signer's nonce.
  pub nonce: u32,

  /// The fee, in SRI, paid to the network for inclusion.
  ///
  /// This fee is paid regardless of the success of any of the calls.
  pub fee: Amount,
}

/// A signature, with context.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ContextualizedSignature {
  /// The explicit context.
  explicit_context: ExplicitContext,
  /// The signature.
  signature: Signature,
}

/// A Serai transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction {
  /// An unsigned transaction.
  Unsigned {
    /// The contained call.
    call: UnsignedCall,
  },
  /// A signed transaction.
  Signed {
    /// The calls.
    ///
    /// These calls are executed atomically. Either all successfully execute or none do. The
    /// transaction's fee is paid regardless.
    calls: SignedCalls,
    /// The signature for this transaction.
    ///
    /// This is not checked on deserializtion and may be invalid.
    contextualized_signature: ContextualizedSignature,
  },
}

impl BorshSerialize for Transaction {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Transaction::Unsigned { call } => {
        /*
          `Signed` `Transaction`s encode the length of their `Vec<Call>` here. Since that `Vec` is
          bound to be non-empty, it will never write `0`, enabling `Unsigned` to use it.

          The benefit to these not overlapping is in the ability to determine if the `Transaction`
          has a signature or not. If this wrote a `1`, for the amount of `Call`s present in the
          `Transaction`, that `Call` would have to be introspected for if its signed or not. With
          the usage of `0`, given how low `MAX_CALLS` is, this `Transaction` can technically be
          defined as an enum of
          `0 Call, 1 Call ContextualizedSignature, 2 Call Call ContextualizedSignature ...`, to
          maintain compatbility with the borsh specification without wrapper functions. The checks
          here on `Call` types/quantity could be moved to later validation functions.
        */
        writer.write_all(&[0])?;
        call.serialize(writer)
      }
      Transaction::Signed { calls, contextualized_signature } => {
        serai_primitives::sp_borsh::borsh_serialize_bounded_vec(&calls.0, writer)?;
        contextualized_signature.serialize(writer)
      }
    }
  }
}

impl BorshDeserialize for Transaction {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut len = [0xff];
    reader.read_exact(&mut len)?;
    let len = len[0];

    if len == 0 {
      let call = Call::deserialize_reader(reader)?;
      if call.is_signed() {
        #[allow(clippy::io_other_error)]
        Err(io::Error::new(io::ErrorKind::Other, "call was signed but marked unsigned"))?;
      }
      Ok(Transaction::Unsigned { call: UnsignedCall(call) })
    } else {
      if u32::from(len) > MAX_CALLS {
        #[allow(clippy::io_other_error)]
        Err(io::Error::new(io::ErrorKind::Other, "too many calls"))?;
      }
      let mut calls = BoundedVec::with_bounded_capacity(len.into());
      for _ in 0 .. len {
        let call = Call::deserialize_reader(reader)?;
        if !call.is_signed() {
          #[allow(clippy::io_other_error)]
          Err(io::Error::new(io::ErrorKind::Other, "call was unsigned but included as signed"))?;
        }
        calls.try_push(call).unwrap();
      }
      let contextualized_signature = ContextualizedSignature::deserialize_reader(reader)?;
      Ok(Transaction::Signed { calls: SignedCalls(calls), contextualized_signature })
    }
  }
}

impl Transaction {
  /// The message to sign to produce a signature.
  pub fn signature_message(
    calls: &SignedCalls,
    implicit_context: &ImplicitContext,
    explicit_context: &ExplicitContext,
  ) -> Vec<u8> {
    let mut message = Vec::with_capacity(
      (calls.0.len() * 64) +
        core::mem::size_of::<ImplicitContext>() +
        core::mem::size_of::<ExplicitContext>(),
    );
    calls.serialize(&mut message).unwrap();
    implicit_context.serialize(&mut message).unwrap();
    explicit_context.serialize(&mut message).unwrap();
    message
  }

  /// The unique hash of this transaction.
  ///
  /// No two transactions on the blockchain will share a hash, making this a unique identifier.
  /// For signed transactions, this is due to the `(signer, nonce)` pair present within the
  /// `ExplicitContext`. For unsigned transactions, this is due to inherent properties of their
  /// execution (e.g. only being able to set a `ValidatorSet`'s keys once).
  pub fn hash(&self) -> [u8; 32] {
    sp_core::blake2_256(&match self {
      Transaction::Unsigned { call } => borsh::to_vec(&call).unwrap(),
      Transaction::Signed {
        calls,
        contextualized_signature: ContextualizedSignature { explicit_context, signature: _ },
      } => {
        // We explicitly don't hash the signature, so signatures can be replaced in the future if
        // desired (such as with half-aggregated Schnorr signatures)
        borsh::to_vec(&(calls, explicit_context)).unwrap()
      }
    })
  }
}

#[cfg(feature = "substrate")]
mod substrate {
  use core::fmt::Debug;
  use alloc::vec;

  use scale::{Encode, Decode};
  use sp_runtime::{
    transaction_validity::*,
    traits::{Verify, ExtrinsicLike, Dispatchable, ValidateUnsigned, Checkable, Applyable},
    Weight,
  };
  #[rustfmt::skip]
  use frame_support::dispatch::{DispatchClass, Pays, DispatchInfo, GetDispatchInfo, PostDispatchInfo};

  use super::*;

  impl Encode for Transaction {
    fn encode(&self) -> Vec<u8> {
      borsh::to_vec(self).unwrap()
    }
  }
  impl Decode for Transaction {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
      serai_primitives::read_scale_as_borsh(input)
    }
  }

  // Clean `Transaction` tracks its memory during decoding, as we do call
  // `Input::on_before_alloc_mem`
  impl scale::DecodeWithMemTracking for Transaction {}

  // Shim `TypeInfo` for `Transaction`
  impl scale_info::TypeInfo for Transaction {
    type Identity = Self;
    fn type_info() -> scale_info::Type {
      scale_info::Type {
        path: scale_info::Path { segments: vec!["serai_abi", "transaction", "Transaction"] },
        type_params: vec![],
        type_def: (scale_info::TypeDefComposite { fields: vec![] }).into(),
        docs: vec![],
      }
    }
  }

  /// The context which transactions are executed in.
  pub trait TransactionContext: 'static + Send + Sync + Clone + PartialEq + Eq + Debug {
    /// The base weight for a signed transaction.
    const SIGNED_WEIGHT: Weight;

    /// The call type for the runtime.
    type RuntimeCall: From<Call>
      + GetDispatchInfo
      + Dispatchable<
        RuntimeOrigin: From<Option<SeraiAddress>>,
        Info = DispatchInfo,
        PostInfo = PostDispatchInfo,
      >;

    /// The implicit context to verify transactions with.
    fn implicit_context() -> ImplicitContext;

    /// If a block is present in the blockchain.
    fn block_is_present_in_blockchain(&self, hash: &BlockHash) -> bool;
    /// The time embedded into the current block.
    ///
    /// Returns `None` if the time has yet to be set.
    fn current_time(&self) -> Option<u64>;
    /// Get the next nonce for an account.
    fn next_nonce(&self, signer: &SeraiAddress) -> u32;
    /// If the signer can pay the SRI fee.
    fn can_pay_fee(
      &self,
      signer: &SeraiAddress,
      fee: Amount,
    ) -> Result<(), TransactionValidityError>;

    /// Begin execution of a transaction.
    fn start_transaction(&self);
    /// Consume the next nonce for an account.
    fn consume_next_nonce(&self, signer: &SeraiAddress);
    /// Have the transaction pay its SRI fee.
    fn pay_fee(&self, signer: &SeraiAddress, fee: Amount) -> Result<(), TransactionValidityError>;
    /// End execution of a transaction.
    fn end_transaction(&self, transaction_hash: [u8; 32]);
  }

  /// A transaction with the context necessary to evaluate it within Substrate.
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct TransactionWithContext<Context: TransactionContext>(
    Transaction,
    #[codec(skip)] Context,
  );

  impl ExtrinsicLike for Transaction {
    fn is_signed(&self) -> Option<bool> {
      Some(matches!(self, Transaction::Signed { .. }))
    }
    fn is_bare(&self) -> bool {
      matches!(self, Transaction::Unsigned { .. })
    }
  }

  impl<Context: TransactionContext> GetDispatchInfo for TransactionWithContext<Context> {
    fn get_dispatch_info(&self) -> DispatchInfo {
      match &self.0 {
        Transaction::Unsigned { call } => DispatchInfo {
          call_weight: Context::RuntimeCall::from(call.0.clone()).get_dispatch_info().call_weight,
          extension_weight: Weight::zero(),
          class: DispatchClass::Operational,
          pays_fee: Pays::No,
        },
        Transaction::Signed { calls, .. } => DispatchInfo {
          call_weight: calls
            .0
            .iter()
            .cloned()
            .map(|call| Context::RuntimeCall::from(call).get_dispatch_info().call_weight)
            .fold(Weight::zero(), |accum, item| accum + item),
          extension_weight: Context::SIGNED_WEIGHT,
          class: DispatchClass::Normal,
          pays_fee: Pays::Yes,
        },
      }
    }
  }

  impl<Context: TransactionContext> Checkable<Context> for Transaction {
    type Checked = TransactionWithContext<Context>;

    fn check(self, context: &Context) -> Result<Self::Checked, TransactionValidityError> {
      match &self {
        Transaction::Unsigned { .. } => {}
        Transaction::Signed {
          calls,
          contextualized_signature: ContextualizedSignature { explicit_context, signature },
        } => {
          if !sp_core::sr25519::Signature::from(*signature).verify(
            Transaction::signature_message(calls, &Context::implicit_context(), explicit_context)
              .as_slice(),
            &sp_core::sr25519::Public::from(explicit_context.signer),
          ) {
            Err(InvalidTransaction::BadProof)?;
          }
        }
      }

      Ok(TransactionWithContext(self, context.clone()))
    }

    #[cfg(feature = "try-runtime")]
    fn unchecked_into_checked_i_know_what_i_am_doing(
      self,
      c: &Context,
    ) -> Result<Self::Checked, TransactionValidityError> {
      // This satisfies the API, not necessarily the intent, yet this fn is only intended to be used
      // within tests. Accordingly, it's fine to be stricter than necessarily
      self.check(c)
    }
  }

  impl<Context: TransactionContext> TransactionWithContext<Context> {
    fn validate_except_fee<V: ValidateUnsigned<Call = Context::RuntimeCall>>(
      &self,
      source: TransactionSource,
      mempool_priority_if_signed: u64,
    ) -> TransactionValidity {
      match &self.0 {
        Transaction::Unsigned { call } => {
          let ValidTransaction { priority: _, requires, provides, longevity: _, propagate: _ } =
            V::validate_unsigned(source, &Context::RuntimeCall::from(call.0.clone()))?;
          Ok(ValidTransaction {
            // We should always try to include unsigned transactions prior to signed
            priority: u64::MAX,
            requires,
            provides,
            // This is valid until included
            longevity: u64::MAX,
            // Ensure this is propagated
            propagate: true,
          })
        }
        Transaction::Signed { calls: _, contextualized_signature } => {
          let ExplicitContext { historic_block, include_by, signer, nonce, fee: _ } =
            &contextualized_signature.explicit_context;
          if !self.1.block_is_present_in_blockchain(historic_block) {
            // We don't know if this is a block from a fundamentally distinct blockchain or a
            // continuation of this blockchain we have yet to sync (which would be `Future`)
            Err(TransactionValidityError::Unknown(UnknownTransaction::CannotLookup))?;
          }
          if let Some(include_by) = *include_by {
            if let Some(current_time) = self.1.current_time() {
              if current_time >= u64::from(include_by) {
                // Since this transaction has a time bound which has passed, error
                Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?;
              }
            } else {
              // Since this transaction has a time bound, yet we don't know the time, error
              Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?;
            }
          }
          match self.1.next_nonce(signer).cmp(nonce) {
            core::cmp::Ordering::Less => {
              Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?
            }
            core::cmp::Ordering::Equal => {}
            core::cmp::Ordering::Greater => {
              Err(TransactionValidityError::Invalid(InvalidTransaction::Future))?
            }
          }

          let requires = if let Some(prior_nonce) = nonce.checked_sub(1) {
            vec![borsh::to_vec(&(signer, prior_nonce)).unwrap()]
          } else {
            vec![]
          };
          let provides = vec![borsh::to_vec(&(signer, nonce)).unwrap()];
          Ok(ValidTransaction {
            priority: mempool_priority_if_signed,
            requires,
            provides,
            // This revalidates the transaction every block. This is required due to this being
            // denominated in blocks, and our transaction expiration being denominated in seconds.
            longevity: 1,
            propagate: true,
          })
        }
      }
    }
  }

  impl<Context: TransactionContext> Applyable for TransactionWithContext<Context> {
    type Call = Context::RuntimeCall;

    fn validate<V: ValidateUnsigned<Call = Context::RuntimeCall>>(
      &self,
      source: TransactionSource,
      info: &DispatchInfo,
      _len: usize,
    ) -> TransactionValidity {
      let mempool_priority_if_signed = match &self.0 {
        Transaction::Unsigned { .. } => {
          // Since this is the priority if signed, and this isn't signed, we return 0
          0
        }
        Transaction::Signed {
          calls: _,
          contextualized_signature:
            ContextualizedSignature { explicit_context: ExplicitContext { signer, fee, .. }, .. },
        } => {
          self.1.can_pay_fee(signer, *fee)?;

          // Prioritize transactions by their fees
          // TODO: Re-evaluate this
          {
            let fee = fee.0;
            Weight::from_all(fee).checked_div_per_component(&info.call_weight).unwrap_or(0)
          }
        }
      };
      self.validate_except_fee::<V>(source, mempool_priority_if_signed)
    }

    fn apply<V: ValidateUnsigned<Call = Context::RuntimeCall>>(
      self,
      _info: &DispatchInfo,
      _len: usize,
    ) -> sp_runtime::ApplyExtrinsicResultWithInfo<PostDispatchInfo> {
      // We use 0 for the mempool priority, as this is no longer in the mempool so it's irrelevant
      self.validate_except_fee::<V>(TransactionSource::InBlock, 0)?;

      // Start the transaction
      self.1.start_transaction();

      let transaction_hash = self.0.hash();

      let res = match self.0 {
        Transaction::Unsigned { call } => {
          let call = Context::RuntimeCall::from(call.0);
          V::pre_dispatch(&call)?;
          match call.dispatch(None.into()) {
            Ok(res) => Ok(Ok(res)),
            // Unsigned transactions should only be included if valid in all regards
            Err(_err) => Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(0))),
          }
        }
        Transaction::Signed {
          calls,
          contextualized_signature:
            ContextualizedSignature { explicit_context: ExplicitContext { signer, fee, .. }, .. },
        } => {
          // Consume the signer's next nonce
          self.1.consume_next_nonce(&signer);
          // Pay the fee
          self.1.pay_fee(&signer, fee)?;

          let _res = frame_support::storage::transactional::with_storage_layer(|| {
            for call in calls.0 {
              let call = Context::RuntimeCall::from(call);
              match call.dispatch(Some(signer).into()) {
                Ok(_res) => {}
                // Because this call errored, don't continue and revert all prior calls
                Err(e) => return Err(e),
              }
            }
            Ok(())
          });

          // We don't care if the individual calls succeeded or failed.
          // The transaction was valid for inclusion and the fee was paid.
          // Either the calls passed, as desired, or they failed and the storage was reverted.
          Ok(Ok(PostDispatchInfo {
            // `None` stands for the worst case, which is what we want
            actual_weight: None,
            // Signed transactions always pay their fee
            // TODO: Do we want to handle this so we can not charge fees on removing genesis
            // liquidity?
            pays_fee: Pays::Yes,
          }))
        }
      };

      // TODO: TransactionSuccess/TransactionFailure event?

      // End the transaction
      self.1.end_transaction(transaction_hash);

      res
    }
  }
}
#[cfg(feature = "substrate")]
pub use substrate::*;

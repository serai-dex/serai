use core::num::NonZero;
use alloc::{vec, vec::Vec};

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
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedCalls(BoundedVec<Call, ConstU32<{ MAX_CALLS }>>);
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
#[derive(Clone, PartialEq, Eq, Debug)]
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

/// The Serai transaction type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
  /// The calls, as defined in Serai's ABI.
  ///
  /// These calls are executed atomically. Either all successfully execute or none do. The
  /// transaction's fee is paid regardless.
  // TODO: if this is unsigned, we only allow a single call. Should we serialize that as 0?
  calls: BoundedVec<Call, ConstU32<{ MAX_CALLS }>>,
  /// The signature, if present.
  contextualized_signature: Option<ContextualizedSignature>,
}

impl BorshSerialize for Transaction {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    // Write the calls
    self.calls.serialize(writer)?;
    // Write the signature, if present. Presence is deterministic to the calls
    if let Some(contextualized_signature) = self.contextualized_signature.as_ref() {
      contextualized_signature.serialize(writer)?;
    }
    Ok(())
  }
}

impl BorshDeserialize for Transaction {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    // Read the calls
    let calls =
      serai_primitives::sp_borsh::borsh_deserialize_bounded_vec::<_, Call, MAX_CALLS>(reader)?;

    // Determine if this is signed or unsigned
    let mut signed = None;
    for call in &calls {
      let call_is_signed = call.is_signed();
      if signed.is_none() {
        signed = Some(call_is_signed)
      };
      if signed != Some(call_is_signed) {
        Err(io::Error::new(io::ErrorKind::Other, "calls were a mixture of signed and unsigned"))?;
      }
    }
    let Some(signed) = signed else {
      Err(io::Error::new(io::ErrorKind::Other, "transaction had no calls"))?
    };

    // Read the signature, if these calls are signed
    let contextualized_signature =
      if signed { Some(<ContextualizedSignature>::deserialize_reader(reader)?) } else { None };

    Ok(Transaction { calls, contextualized_signature })
  }
}

impl Transaction {
  /// The message to sign to produce a signature, for calls which may or may not be signed and are
  /// unchecked.
  fn signature_message_unchecked(
    calls: &[Call],
    implicit_context: &ImplicitContext,
    explicit_context: &ExplicitContext,
  ) -> Vec<u8> {
    let mut message = Vec::with_capacity(
      (calls.len() * 64) +
        core::mem::size_of::<ImplicitContext>() +
        core::mem::size_of::<ExplicitContext>(),
    );
    calls.serialize(&mut message).unwrap();
    implicit_context.serialize(&mut message).unwrap();
    explicit_context.serialize(&mut message).unwrap();
    message
  }

  /// The message to sign to produce a signature.
  pub fn signature_message(
    calls: &SignedCalls,
    implicit_context: &ImplicitContext,
    explicit_context: &ExplicitContext,
  ) -> Vec<u8> {
    Self::signature_message_unchecked(&calls.0, implicit_context, explicit_context)
  }

  /// A transaction with signed calls.
  pub fn signed(
    calls: SignedCalls,
    explicit_context: ExplicitContext,
    signature: Signature,
  ) -> Self {
    let calls = calls.0;
    Self {
      calls,
      contextualized_signature: Some(ContextualizedSignature { explicit_context, signature }),
    }
  }

  /// A transaction with an unsigned call.
  pub fn unsigned(call: UnsignedCall) -> Self {
    let call = call.0;
    Self {
      calls: vec![call.clone()]
        .try_into()
        .expect("couldn't convert a length-1 Vec to a BoundedVec"),
      contextualized_signature: None,
    }
  }

  /// If the transaction is signed.
  pub fn is_signed(&self) -> bool {
    self.calls[0].is_signed()
  }
}

#[cfg(feature = "substrate")]
mod substrate {
  use core::{marker::PhantomData, fmt::Debug};

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
      struct ScaleRead<'a, I: scale::Input>(&'a mut I, Option<scale::Error>);
      impl<I: scale::Input> borsh::io::Read for ScaleRead<'_, I> {
        fn read(&mut self, buf: &mut [u8]) -> borsh::io::Result<usize> {
          let remaining_len = self.0.remaining_len().map_err(|err| {
            self.1 = Some(err);
            borsh::io::Error::new(borsh::io::ErrorKind::Other, "")
          })?;
          // If we're still calling `read`, we try to read at least one more byte
          let to_read = buf.len().min(remaining_len.unwrap_or(1));
          self.0.read(&mut buf[.. to_read]).map_err(|err| {
            self.1 = Some(err);
            borsh::io::Error::new(borsh::io::ErrorKind::Other, "")
          })?;
          Ok(to_read)
        }
      }
      let mut input = ScaleRead(input, None);
      match Self::deserialize_reader(&mut input) {
        Ok(res) => Ok(res),
        Err(_) => Err(input.1.unwrap()),
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
    fn implicit_context() -> &'static ImplicitContext;

    /// If a block is present in the blockchain.
    fn block_is_present_in_blockchain(&self, hash: &BlockHash) -> bool;
    /// The time embedded into the current block.
    ///
    /// Returns `None` if the time has yet to be set.
    fn current_time(&self) -> Option<u64>;
    /// The next nonce for an account.
    fn next_nonce(&self, signer: &SeraiAddress) -> u32;
    /// Have the transaction pay its SRI fee.
    fn pay_fee(&self, signer: &SeraiAddress, fee: Amount) -> Result<(), TransactionValidityError>;
  }

  /// A transaction with the context necessary to evaluate it within Substrate.
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct TransactionWithContext<Context: TransactionContext>(
    Transaction,
    #[codec(skip)] PhantomData<Context>,
  );

  impl ExtrinsicLike for Transaction {
    fn is_signed(&self) -> Option<bool> {
      Some(Transaction::is_signed(self))
    }
    fn is_bare(&self) -> bool {
      !Transaction::is_signed(self)
    }
  }

  impl<Context: TransactionContext> GetDispatchInfo for TransactionWithContext<Context> {
    fn get_dispatch_info(&self) -> DispatchInfo {
      let (extension_weight, class, pays_fee) = if Transaction::is_signed(&self.0) {
        (Context::SIGNED_WEIGHT, DispatchClass::Normal, Pays::Yes)
      } else {
        (Weight::zero(), DispatchClass::Operational, Pays::No)
      };
      DispatchInfo {
        call_weight: self
          .0
          .calls
          .iter()
          .cloned()
          .map(|call| Context::RuntimeCall::from(call).get_dispatch_info().call_weight)
          .fold(Weight::zero(), |accum, item| accum + item),
        extension_weight,
        class,
        pays_fee,
      }
    }
  }

  impl<Context: TransactionContext> Checkable<Context> for Transaction {
    type Checked = TransactionWithContext<Context>;

    fn check(self, context: &Context) -> Result<Self::Checked, TransactionValidityError> {
      if let Some(ContextualizedSignature { explicit_context, signature }) =
        &self.contextualized_signature
      {
        let ExplicitContext { historic_block, include_by, signer, nonce, fee } = &explicit_context;
        if !context.block_is_present_in_blockchain(historic_block) {
          // We don't know if this is a block from a fundamentally distinct blockchain or a
          // continuation of this blockchain we have yet to sync (which would be `Future`)
          Err(TransactionValidityError::Unknown(UnknownTransaction::CannotLookup))?;
        }
        if let Some(include_by) = *include_by {
          if let Some(current_time) = context.current_time() {
            if current_time >= u64::from(include_by) {
              // Since this transaction has a time bound which has passed, error
              Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?;
            }
          } else {
            // Since this transaction has a time bound, yet we don't know the time, error
            Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?;
          }
        }
        match context.next_nonce(signer).cmp(nonce) {
          core::cmp::Ordering::Less => {
            Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?
          }
          core::cmp::Ordering::Equal => {}
          core::cmp::Ordering::Greater => {
            Err(TransactionValidityError::Invalid(InvalidTransaction::Future))?
          }
        }
        if !sp_core::sr25519::Signature::from(*signature).verify(
          Transaction::signature_message_unchecked(
            &self.calls,
            Context::implicit_context(),
            explicit_context,
          )
          .as_slice(),
          &sp_core::sr25519::Public::from(*signer),
        ) {
          Err(sp_runtime::transaction_validity::InvalidTransaction::BadProof)?;
        }
        context.pay_fee(signer, *fee)?;
      }

      Ok(TransactionWithContext(self, PhantomData))
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

  impl<Context: TransactionContext> Applyable for TransactionWithContext<Context> {
    type Call = Context::RuntimeCall;

    fn validate<V: ValidateUnsigned<Call = Context::RuntimeCall>>(
      &self,
      source: sp_runtime::transaction_validity::TransactionSource,
      info: &DispatchInfo,
      _len: usize,
    ) -> sp_runtime::transaction_validity::TransactionValidity {
      if !self.0.is_signed() {
        let ValidTransaction { priority: _, requires, provides, longevity: _, propagate: _ } =
          V::validate_unsigned(source, &Context::RuntimeCall::from(self.0.calls[0].clone()))?;
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
      } else {
        let explicit_context = &self.0.contextualized_signature.as_ref().unwrap().explicit_context;
        let requires = if let Some(prior_nonce) = explicit_context.nonce.checked_sub(1) {
          vec![borsh::to_vec(&(explicit_context.signer, prior_nonce)).unwrap()]
        } else {
          vec![]
        };
        let provides =
          vec![borsh::to_vec(&(explicit_context.signer, explicit_context.nonce)).unwrap()];
        Ok(ValidTransaction {
          // Prioritize transactions by their fees
          priority: {
            let fee = explicit_context.fee.0;
            Weight::from_all(fee).checked_div_per_component(&info.call_weight).unwrap_or(0)
          },
          requires,
          provides,
          // This revalidates the transaction every block. This is required due to this being
          // denominated in blocks, and our transaction expiration being denominated in seconds.
          longevity: 1,
          propagate: true,
        })
      }
    }

    fn apply<V: ValidateUnsigned<Call = Context::RuntimeCall>>(
      mut self,
      _info: &DispatchInfo,
      _len: usize,
    ) -> sp_runtime::ApplyExtrinsicResultWithInfo<PostDispatchInfo> {
      if !self.0.is_signed() {
        let call = Context::RuntimeCall::from(self.0.calls.remove(0));
        V::pre_dispatch(&call)?;
        match call.dispatch(None.into()) {
          Ok(res) => Ok(Ok(res)),
          // Unsigned transactions should only be included if valid in all regards
          // This isn't actually a "mandatory" but the intent is the same
          Err(_err) => Err(TransactionValidityError::Invalid(InvalidTransaction::BadMandatory)),
        }
      } else {
        Ok(frame_support::storage::transactional::with_storage_layer(|| {
          for call in self.0.calls {
            let call = Context::RuntimeCall::from(call);
            match call.dispatch(
              Some(self.0.contextualized_signature.as_ref().unwrap().explicit_context.signer)
                .into(),
            ) {
              Ok(_res) => {}
              // Because this call errored, don't continue and revert all prior calls
              Err(e) => Err(e)?,
            }
          }
          // Since all calls errored, return all
          Ok(PostDispatchInfo {
            // `None` stands for the worst case, which is what we want
            actual_weight: None,
            // Signed transactions always pay their fee
            // TODO: Do we want to handle this so we can not charge fees on removing genesis
            // liquidity?
            pays_fee: Pays::Yes,
          })
        }))
      }
    }
  }
}
#[cfg(feature = "substrate")]
pub use substrate::*;

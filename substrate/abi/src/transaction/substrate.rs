use core::fmt::Debug;
use alloc::vec;

use scale::{Encode, Decode};
use sp_runtime::{
  transaction_validity::*,
  traits::{
    Verify as _, ExtrinsicLike, ExtrinsicCall, Dispatchable, ValidateUnsigned, Checkable, Applyable,
  },
  Weight,
};
#[rustfmt::skip]
use frame_support::dispatch::{DispatchClass, Pays, DispatchInfo, GetDispatchInfo, PostDispatchInfo};

use super::*;

serai_primitives::borsh_as_scale!(Transaction);

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

  /// The size of the current block.
  fn current_block_size(&self) -> usize;

  /// If a block is present in the blockchain.
  fn block_is_present_in_blockchain(&self, hash: &BlockHash) -> bool;
  /// The time embedded into the current block.
  fn current_time(&self) -> u64;
  /// Get the next nonce for an account.
  fn next_nonce(&self, signer: &SeraiAddress) -> u32;
  /// If the signer can pay the SRI fee.
  fn can_pay_fee(&self, signer: &SeraiAddress, fee: Amount)
    -> Result<(), TransactionValidityError>;

  /// Begin execution of a transaction.
  fn start_transaction(&self, len: usize);
  /// Consume the next nonce for an account.
  ///
  /// This MUST NOT be called if the next nonce is `u32::MAX`. The caller MAY panic in that case.
  fn consume_next_nonce(&self, signer: &SeraiAddress);
  /// Have the transaction pay its SRI fee.
  fn pay_fee(&self, signer: &SeraiAddress, fee: Amount) -> Result<(), TransactionValidityError>;
  /// End execution of a transaction.
  fn end_transaction(&self, transaction_hash: [u8; 32]);
}

/// A transaction with the context necessary to evaluate it within Substrate.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
pub struct TransactionWithContext<Context: TransactionContext>(Transaction, #[codec(skip)] Context);

impl ExtrinsicLike for Transaction {
  fn is_signed(&self) -> Option<bool> {
    Some(matches!(self, Transaction::Signed { .. }))
  }
  fn is_bare(&self) -> bool {
    matches!(self, Transaction::Unsigned { .. })
  }
}

impl ExtrinsicCall for Transaction {
  type Call = Self;
  fn call(&self) -> &Self {
    self
  }
  fn into_call(self) -> Self {
    self
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
    len: usize,
    source: TransactionSource,
    mempool_priority_if_signed: u64,
  ) -> TransactionValidity {
    if self.1.current_block_size().saturating_add(len) > crate::Block::SIZE_LIMIT {
      Err(TransactionValidityError::Invalid(InvalidTransaction::ExhaustsResources))?;
    }

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
          if self.1.current_time() >= u64::from(include_by) {
            // Since this transaction has a time bound which has passed, error
            Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?;
          }
        }

        {
          let next_nonce = self.1.next_nonce(signer);
          if next_nonce == u32::MAX {
            Err(TransactionValidityError::Invalid(InvalidTransaction::BadSigner))?;
          }
          match next_nonce.cmp(nonce) {
            core::cmp::Ordering::Less => {
              Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?
            }
            core::cmp::Ordering::Equal => {}
            core::cmp::Ordering::Greater => {
              Err(TransactionValidityError::Invalid(InvalidTransaction::Future))?
            }
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
    len: usize,
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
    self.validate_except_fee::<V>(len, source, mempool_priority_if_signed)
  }

  fn apply<V: ValidateUnsigned<Call = Context::RuntimeCall>>(
    self,
    _info: &DispatchInfo,
    len: usize,
  ) -> sp_runtime::ApplyExtrinsicResultWithInfo<PostDispatchInfo> {
    // We use 0 for the mempool priority, as this is no longer in the mempool so it's irrelevant
    self.validate_except_fee::<V>(len, TransactionSource::InBlock, 0)?;

    // Start the transaction
    self.1.start_transaction(len);

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

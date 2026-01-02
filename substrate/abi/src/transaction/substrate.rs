use core::{fmt::Debug, time::Duration};
use alloc::vec;

use scale::{Encode, Decode};
use sp_runtime::{
  transaction_validity::*,
  traits::{
    Verify as _, ExtrinsicLike, ExtrinsicCall, Dispatchable, ValidateUnsigned, Checkable, Applyable,
  },
  Weight,
};
use frame_support::dispatch::{DispatchClass, Pays, DispatchInfo, GetDispatchInfo, PostDispatchInfo};

use serai_primitives::crypto::Signature;

use super::*;

serai_primitives::borsh_as_scale!(Transaction);

// Implement `ExtrinsicLike` for `Transaction`.
//
// This is required for `sp_runtime::traits::Block` and for `Transaction: ExtrinsicCall`.
impl ExtrinsicLike for Transaction {
  fn is_bare(&self) -> bool {
    matches!(self, Transaction::Unsigned { .. })
  }
}

// Implement `ExtrinsicCall` for `Transaction`.
//
// This is required by `frame_support::construct_runtime`.
impl ExtrinsicCall for Transaction {
  type Call = Self;
  fn call(&self) -> &Self {
    self
  }
  fn into_call(self) -> Self {
    self
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

  /// The size of the current block.
  fn current_block_size(&self) -> usize;

  /// If a block is present in the blockchain.
  fn block_is_present_in_blockchain(&self, hash: &BlockHash) -> bool;
  /// The time embedded into the current block.
  fn current_time(&self) -> u64;
  /// Get the next nonce for an account.
  fn next_nonce(&self, signer: &SeraiAddress) -> u32;
  /// If the signer can pay the fee, denominated in SRI.
  fn can_pay_fee(&self, signer: &SeraiAddress, fee: Amount)
    -> Result<(), TransactionValidityError>;

  /// Begin execution of a transaction.
  fn start_transaction(&self, len: usize);
  /// Consume the next nonce for an account.
  ///
  /// This MUST NOT be called if the next nonce is `u32::MAX`. The function MAY panic in that case.
  fn consume_next_nonce(&self, signer: &SeraiAddress);
  /// Have the transaction pay its SRI fee.
  fn pay_fee(&self, signer: &SeraiAddress, fee: Amount) -> Result<(), TransactionValidityError>;
  /// End execution of a transaction.
  fn end_transaction(&self, transaction_hash: [u8; 32]);
}

/// A transaction with the context necessary to evaluate it within Substrate.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
pub struct TransactionWithContext<Context: TransactionContext> {
  transaction: Transaction,
  #[codec(skip)]
  context: Context,
}

impl<Context: TransactionContext> GetDispatchInfo for TransactionWithContext<Context> {
  fn get_dispatch_info(&self) -> DispatchInfo {
    match &self.transaction {
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

// Next, we implement all of the `trait`s necessary for `frame_executive`.
impl<Context: TransactionContext> Checkable<Context> for Transaction {
  type Checked = TransactionWithContext<Context>;

  fn check(self, context: &Context) -> Result<Self::Checked, TransactionValidityError> {
    match &self {
      Transaction::Unsigned { .. } => {}
      Transaction::Signed {
        calls,
        contextualized_signature: ContextualizedSignature { explicit_context, signature },
      } => {
        match signature {
          Signature::Ristretto(signature) => {
            // We interpret the address directly as a Ristretto group element
            let verification_key = sp_core::sr25519::Public::from(explicit_context.signer);
            if !sp_core::sr25519::Signature::from(*signature).verify(
              Transaction::signature_message(&Context::implicit_context(), calls, explicit_context)
                .as_slice(),
              &verification_key,
            ) {
              Err(InvalidTransaction::BadProof)?;
            }
          }
        }
      }
    }

    Ok(TransactionWithContext { transaction: self, context: context.clone() })
  }

  #[cfg(feature = "try-runtime")]
  fn unchecked_into_checked_i_know_what_i_am_doing(
    self,
    context: &Context,
  ) -> Result<Self::Checked, TransactionValidityError> {
    Ok(TransactionWithContext { transaction: self, context: context.clone() })
  }
}

impl<Context: TransactionContext> TransactionWithContext<Context> {
  fn validate_except_fee<V: ValidateUnsigned<Call = Context::RuntimeCall>>(
    &self,
    len: usize,
    source: TransactionSource,
    mempool_priority_if_signed: u64,
  ) -> TransactionValidity {
    // Check the block size is respected
    if self.context.current_block_size().saturating_add(len) > crate::Block::SIZE_LIMIT {
      Err(TransactionValidityError::Invalid(InvalidTransaction::ExhaustsResources))?;
    }

    match &self.transaction {
      Transaction::Unsigned { call } => {
        V::validate_unsigned(source, &Context::RuntimeCall::from(call.0.clone()))
      }
      Transaction::Signed { calls: _, contextualized_signature } => {
        let ExplicitContext { historic_block, include_by, signer, nonce, fee: _ } =
          &contextualized_signature.explicit_context;
        if !self.context.block_is_present_in_blockchain(historic_block) {
          // We don't know if this is a block from a fundamentally distinct blockchain or a
          // continuation of this blockchain we have yet to sync (which would be `Future`)
          Err(TransactionValidityError::Unknown(UnknownTransaction::CannotLookup))?;
        }
        if let Some(include_by) = *include_by {
          if self.context.current_time() >= u64::from(include_by) {
            // Since this transaction has a time bound which has passed, error
            Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?;
          }
        }

        let tag_for_nonce = |nonce| borsh::to_vec(&(signer, nonce)).unwrap();
        let mut requires = vec![];
        {
          let next_nonce = self.context.next_nonce(signer);
          // `consume_next_nonce` is allowed to panic if we attempt to consume this nonce, so we
          // invalidate the account at this point (which should be impractical anyways)
          if next_nonce == u32::MAX {
            Err(TransactionValidityError::Invalid(InvalidTransaction::BadSigner))?;
          }
          match next_nonce.cmp(nonce) {
            core::cmp::Ordering::Less => {
              Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))?
            }
            core::cmp::Ordering::Equal => {}
            // Because this is greater than the on-chain nonce, add a requirement of the prior
            // nonce
            core::cmp::Ordering::Greater => requires.push(tag_for_nonce(*nonce - 1)),
          }
        }
        let provides = vec![tag_for_nonce(*nonce)];

        Ok(ValidTransaction {
          priority: mempool_priority_if_signed,
          requires,
          provides,
          longevity: if include_by.is_some() {
            // This revalidates the transaction every block. This is required due to this being
            // denominated in blocks, and our transaction expiration being denominated in seconds
            1
          } else {
            Duration::from_mins(10).as_secs() /
              serai_primitives::constants::TARGET_BLOCK_TIME.as_secs()
          },
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
    let mempool_priority_if_signed = match &self.transaction {
      Transaction::Unsigned { .. } => {
        // Since this is the priority if signed, and this isn't signed, we return 0
        0
      }
      Transaction::Signed {
        calls: _,
        contextualized_signature:
          ContextualizedSignature { explicit_context: ExplicitContext { signer, fee, .. }, .. },
      } => {
        self.context.can_pay_fee(signer, *fee)?;

        // Prioritize transactions by their fees
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
    info: &DispatchInfo,
    len: usize,
  ) -> sp_runtime::ApplyExtrinsicResultWithInfo<PostDispatchInfo> {
    /*
      While the sane assumption would be this is only called after `Applyable::validate`, meaning
      we don't have to perform validation again here, that isn't strictly guaranteed. We
      explicitly perform validation again here to be sure.

      We could cache the validation in a boolean, to ensure it doesn't occur twice, but that
      assumes the environment when cached is the environment now, which isn't sane to guarantee.

      We use `0` for the mempool priority, as this is no longer in the mempool so it's irrelevant.
    */
    let validation_info = self.validate_except_fee::<V>(len, TransactionSource::InBlock, 0)?;
    // We also have to apply the additional check no requirements are outstanding
    if !validation_info.requires.is_empty() {
      Err(TransactionValidityError::Invalid(InvalidTransaction::Future))?;
    }

    // Start the transaction
    self.context.start_transaction(len);

    let transaction_hash = self.transaction.hash();

    let res = match self.transaction {
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
        self.context.consume_next_nonce(&signer);
        // Pay the fee
        self.context.pay_fee(&signer, fee)?;

        /*
          The `actual_weight` is compared to the total weight from the `DispatchInfo`, not the call
          weight alone. Accordingly, we need to include the base weight for a signed transaction
          here.
        */
        let mut actual_weight = Context::SIGNED_WEIGHT;
        let _res = frame_support::storage::transactional::with_storage_layer(|| {
          for call in calls.0 {
            let call = Context::RuntimeCall::from(call);
            actual_weight += call.get_dispatch_info().call_weight;
            match call.dispatch(Some(signer).into()) {
              Ok(_res) => {}
              // Because this call errored, don't continue and revert all prior calls
              Err(e) => return Err(e),
            }
          }
          debug_assert_eq!(actual_weight, info.total_weight());
          Ok(())
        });

        /*
          Regardless of if the individual calls succeeded or failed, we want to note this
          transaction itself was valid, having been properly signed and paid its fee.
        */
        Ok(Ok(PostDispatchInfo {
          actual_weight: Some(actual_weight),
          /*
            Because this transaction was queued for inclusion, it should pay its fee.
            Additionally, this must be `Pays::Yes`, because we already deducted the fee
            (with no mechanism to refund it).
          */
          pays_fee: Pays::Yes,
        }))
      }
    };

    // End the transaction
    self.context.end_transaction(transaction_hash);

    res
  }
}

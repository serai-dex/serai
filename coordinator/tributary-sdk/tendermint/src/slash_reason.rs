use core::fmt;

use crate::{
  BlockNumber, RoundNumber, Validator, ValidatorSet, Signature, AggregateSignature,
  SignatureScheme, Block, Commit, ValidRound, Data, Message,
};

// We want to replace `borsh`'s bounds, which requires specifying bounds, so we stub them with this
#[cfg(feature = "alloc")]
trait NoBounds {}
#[cfg(feature = "alloc")]
impl<T> NoBounds for T {}

/// A pair of datas which equivocate with each other.
///
/// These represent two separate [`Data`]s which were published with the same block number and
/// round number, by the same signer, when an honest validator will always only publish one such
/// message.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub(crate) enum EquivocatingData<S: Signature, A: AggregateSignature, B: Block> {
  Proposal {
    first_valid_round: Option<ValidRound<A>>,
    #[borsh(bound(
      serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
      deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
    ))]
    first_proposal: B::Hash,
    second_valid_round: Option<ValidRound<A>>,
    #[borsh(bound(
      serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
      deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
    ))]
    second_proposal: B::Hash,
  },
  Prevote {
    #[borsh(bound(
      serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
      deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
    ))]
    first_block: Option<B::Hash>,
    #[borsh(bound(
      serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
      deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
    ))]
    second_block: Option<B::Hash>,
  },
  Precommit {
    #[borsh(bound(
      serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
      deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
    ))]
    first_block_and_precommit_signature: Option<(B::Hash, S)>,
    #[borsh(bound(
      serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
      deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
    ))]
    second_block_and_precommit_signature: Option<(B::Hash, S)>,
  },
}

impl<S: Signature, A: AggregateSignature, B: Block<Hash: fmt::Debug>> fmt::Debug
  for EquivocatingData<S, A, B>
{
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Proposal { first_valid_round, first_proposal, second_valid_round, second_proposal } => {
        formatter
          .debug_struct("EquivocatingData::Proposal")
          .field("first_valid_round", first_valid_round)
          .field("first_proposal", first_proposal)
          .field("second_valid_round", second_valid_round)
          .field("second_proposal", second_proposal)
          .finish_non_exhaustive()
      }
      Self::Prevote { first_block, second_block } => formatter
        .debug_struct("EquivocatingData::Prevote")
        .field("first_block", first_block)
        .field("second_block", second_block)
        .finish_non_exhaustive(),
      Self::Precommit {
        first_block_and_precommit_signature,
        second_block_and_precommit_signature,
      } => formatter
        .debug_struct("EquivocatingData::Precommit")
        .field(
          "first_block",
          &first_block_and_precommit_signature.as_ref().map(|(block, _precommit_signature)| block),
        )
        .field(
          "second_block",
          &second_block_and_precommit_signature.as_ref().map(|(block, _precommit_signature)| block),
        )
        .finish_non_exhaustive(),
    }
  }
}

/// A stub block which satisfies the `Block` trait from only a hash.
///
/// We use this to build a `Data` (expecting `B: Block`) from solely a hash, as for the purposes of
/// verifying its signature.
#[derive(Clone)]
#[repr(transparent)]
struct StubBlock<'hash>(&'hash [u8]);
impl<'hash> Block for StubBlock<'hash> {
  type Hash = &'hash [u8];
  fn hash(&self) -> Self::Hash {
    self.0
  }
}

impl<S: Signature, A: AggregateSignature, B: Block> EquivocatingData<S, A, B> {
  fn split(&self) -> (Data<S, A, StubBlock<'_>>, Data<S, A, StubBlock<'_>>) {
    match self {
      EquivocatingData::Proposal {
        first_valid_round,
        first_proposal,
        second_valid_round,
        second_proposal,
      } => (
        Data::Proposal {
          valid_round: first_valid_round.clone(),
          proposal: StubBlock(first_proposal.as_ref()),
        },
        Data::Proposal {
          valid_round: second_valid_round.clone(),
          proposal: StubBlock(second_proposal.as_ref()),
        },
      ),
      EquivocatingData::Prevote { first_block, second_block } => (
        Data::Prevote { block: first_block.as_ref().map(AsRef::as_ref) },
        Data::Prevote { block: second_block.as_ref().map(AsRef::as_ref) },
      ),
      EquivocatingData::Precommit {
        first_block_and_precommit_signature,
        second_block_and_precommit_signature,
      } => (
        Data::Precommit {
          block_and_precommit_signature: first_block_and_precommit_signature
            .as_ref()
            .map(|(block, signature)| (block.as_ref(), signature.clone())),
        },
        Data::Precommit {
          block_and_precommit_signature: second_block_and_precommit_signature
            .as_ref()
            .map(|(block, signature)| (block.as_ref(), signature.clone())),
        },
      ),
    }
  }
}

/// Evidence for a slash.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub(crate) enum Evidence<S: Signature, A: AggregateSignature, B: Block> {
  /// The validator equivocated, sending two distinct messages when they should have only sent one.
  Equivocation {
    #[borsh(bound(
      serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
      deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
    ))]
    data: EquivocatingData<S, A, B>,
    first_signature: S,
    second_signature: S,
  },
  /// The validator created an invalid proposal.
  InvalidProposal {
    valid_round: Option<ValidRound<A>>,
    #[borsh(bound(
      serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
      deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
    ))]
    proposal: B::Hash,
    signature: S,
  },
  /// The validator created an invalid precommit.
  InvalidPrecommit {
    #[borsh(bound(
      serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
      deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
    ))]
    block: B::Hash,
    precommit_signature: S,
    signature: S,
  },
}

impl<S: Signature, A: AggregateSignature, B: Block<Hash: fmt::Debug>> fmt::Debug
  for Evidence<S, A, B>
{
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Equivocation { data, first_signature: _, second_signature: _ } => {
        formatter.debug_struct("Evidence::Equivocation").field("data", data).finish_non_exhaustive()
      }
      Self::InvalidProposal { valid_round, proposal, signature: _ } => formatter
        .debug_struct("Evidence::InvalidProposal")
        .field("valid_round", valid_round)
        .field("proposal", proposal)
        .finish_non_exhaustive(),
      Self::InvalidPrecommit { block, precommit_signature: _, signature: _ } => formatter
        .debug_struct("Evidence::InvalidPrecommit")
        .field("block", block)
        .finish_non_exhaustive(),
    }
  }
}

/// A reason to slash a validator.
///
/// This contains the necessary evidence to convince other validators of this slash.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct SlashReason<S: Signature, A: AggregateSignature, B: Block> {
  pub(crate) block_number: BlockNumber,
  pub(crate) round_number: RoundNumber,
  #[borsh(bound(
    serialize = "B: NoBounds, B::Hash: borsh::BorshSerialize",
    deserialize = "B: NoBounds, B::Hash: borsh::BorshDeserialize"
  ))]
  pub(crate) evidence: Evidence<S, A, B>,
}

impl<S: Signature, A: AggregateSignature, B: Block<Hash: fmt::Debug>> fmt::Debug
  for SlashReason<S, A, B>
{
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let Self { block_number, round_number, evidence } = self;
    formatter
      .debug_struct("SlashReason")
      .field("block_number", block_number)
      .field("round_number", round_number)
      .field("evidence", evidence)
      .finish()
  }
}

/// An invalid reason for a slash was provided.
#[derive(Clone, Debug)]
pub struct InvalidReason;

impl<S: Signature, A: AggregateSignature, B: Block> SlashReason<S, A, B> {
  /// Verify the reasoning for this slash.
  pub fn verify<V: Validator>(
    &self,
    genesis: impl AsRef<[u8]>,
    validator_set: &impl ValidatorSet<Validator = V>,
    signature_scheme: &impl SignatureScheme<Validator = V, Signature = S, AggregateSignature = A>,
    validator: V,
  ) -> Result<(), InvalidReason> {
    let verify_message = |data, signature| {
      if !signature_scheme.verify(
        &validator,
        Message::<V, S, A, _>::signature_message(
          genesis.as_ref(),
          self.block_number,
          self.round_number,
          &data,
        ),
        signature,
      ) {
        // If this message's signature was invalid, this wasn't actually a message from the accused
        // validator, and this is an invalid reason to slash the accused validator
        Err(InvalidReason)?;
      }

      Ok(())
    };

    match &self.evidence {
      Evidence::Equivocation { data, first_signature, second_signature } => {
        let (data1, data2) = data.split();

        // If these aren't distinct, this isn't an equivocation
        if data1 == data2 {
          Err(InvalidReason)?;
        }

        // Check these were both signed by this validator
        for (data, signature) in [(data1, first_signature), (data2, second_signature)] {
          verify_message(data, signature)?;
        }
      }
      Evidence::InvalidProposal { valid_round, proposal, signature } => {
        // Check this was a proposal message signed by this validator
        verify_message(
          Data::Proposal {
            valid_round: valid_round.clone(),
            proposal: StubBlock(proposal.as_ref()),
          },
          signature,
        )?;

        // If the structure of this proposal was valid, this is an invalid reason to slash this
        // validator
        if (validator == validator_set.proposer(self.block_number, self.round_number)) &&
          match valid_round {
            Some(ValidRound { round_number, aggregate_signature }) => {
              ((*round_number) < self.round_number) &&
                signature_scheme
                  .verify_aggregate(
                    Message::<V, S, A, B>::signature_message(
                      genesis.as_ref(),
                      self.block_number,
                      *round_number,
                      &Data::Prevote { block: Some(*proposal) },
                    ),
                    aggregate_signature,
                  )
                  .is_ok_and(|validators| {
                    crate::validators_satisfy_threshold(validators, validator_set)
                  })
            }
            None => true,
          }
        {
          Err(InvalidReason)?;
        }
      }
      Evidence::InvalidPrecommit { block, precommit_signature, signature } => {
        // Check this was a precommit message signed by this validator
        verify_message(
          Data::Precommit {
            block_and_precommit_signature: Some((block.as_ref(), precommit_signature.clone())),
          },
          signature,
        )?;

        // If the inner signature is valid, this a valid precommit and an invalid reason to slash
        // the accused validator
        if Commit::verify_precommit(
          signature_scheme,
          &validator,
          genesis,
          self.block_number,
          self.round_number,
          block,
          precommit_signature,
        ) {
          Err(InvalidReason)?;
        }
      }
    }

    Ok(())
  }
}
